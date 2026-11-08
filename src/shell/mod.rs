pub mod arith;
pub mod complete;
pub mod env;
mod exec;
mod expand;
pub mod line;
pub mod parser;
mod pending;
mod redirect;

pub use pending::Pending;

use crate::commands;
use crate::persona::Persona;
use crate::vfs::{snapshot, NodeId, Vfs};
use env::Env;

#[derive(Default)]
pub struct Output {
    pub text: String,

    pub stdout: String,

    pub stderr: String,

    pub status: i32,

    pub exit: bool,
}

impl Output {
    fn push(&mut self, stdout: &str, stderr: &str) {
        self.text.push_str(stderr);
        self.text.push_str(stdout);
        self.stdout.push_str(stdout);
        self.stderr.push_str(stderr);
    }

    fn written(stdout: &str, stderr: &str, status: i32) -> Self {
        let mut out = Output {
            status,
            ..Output::default()
        };
        out.push(stdout, stderr);
        out
    }

    fn prepend_stderr(&mut self, text: &str) {
        self.text.insert_str(0, text);
        self.stderr.insert_str(0, text);
    }
}

#[derive(Debug, Clone)]
pub enum Capture {
    Download {
        tool: String,

        url: String,

        dest: String,
    },

    ScriptCommand {
        line: String,

        status: i32,
    },

    PasswordChange {
        target: String,

        password: String,
    },

    SuAuth {
        target: String,

        password: String,
    },
}

#[derive(Clone)]
pub enum Screen {
    Top(commands::system::TopScreen),

    Editor(commands::text::EditorScreen),

    Listen,
}

const CONNECTION_VARS: &[&str] = &["SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY"];

const ROOT_USER: &str = "root";
const ROOT_HOME: &str = "/root";
const ROOT_UID: u32 = 0;
const REGULAR_UID: u32 = 1000;
const SHELL_PID: u32 = 1337;
const HOME_DIR_MODE: u32 = 0o755;
const REGULAR_FILE_MODE: u32 = 0o644;

pub struct Shell {
    pub vfs: Vfs,

    pub env: Env,

    pub cwd: NodeId,

    pub home: NodeId,

    pub prev_cwd: NodeId,

    pub username: String,

    pub hostname: String,

    pub uid: u32,

    pub gid: u32,

    pub last_status: i32,

    pub pid: u32,

    pub login: i64,

    pub nesting: u32,

    subst_budget: usize,

    subst_stderr: String,

    pub stdin: Option<String>,

    pub stdout_is_tty: bool,

    pub interactive: bool,

    pub history: Vec<String>,

    pub captures: Vec<Capture>,

    pub pending: Option<Pending>,

    pub screen: Option<Screen>,

    subst_depth: u32,

    pub persona: Persona,

    heredoc_stdin: Option<String>,

    pub heredoc_log: Option<String>,
}

impl Shell {
    pub fn new(username: &str, hostname: &str) -> Self {
        Self::with_persona(username, hostname, Persona::sample())
    }

    pub fn with_persona(username: &str, hostname: &str, persona: Persona) -> Self {
        let mut vfs = snapshot::build(hostname, &persona);
        let account = Account::named(username);
        let home = account.ensure_home(&mut vfs);
        let env = Env::login(account.name, &account.home, hostname);

        Self {
            vfs,
            env,
            cwd: home,
            home,
            prev_cwd: home,
            username: account.name.to_string(),
            hostname: hostname.to_string(),
            uid: account.uid,
            gid: account.gid,
            last_status: 0,
            pid: SHELL_PID,
            login: crate::clock::now(),
            nesting: 0,
            subst_budget: commands::MAX_COMMAND_OUTPUT_BYTES,
            subst_stderr: String::new(),
            stdin: None,
            stdout_is_tty: true,
            interactive: true,
            screen: None,
            subst_depth: 0,
            heredoc_stdin: None,
            heredoc_log: None,
            persona,
            history: Vec::new(),
            captures: Vec::new(),
            pending: None,
        }
    }

    pub const MAX_HISTORY: usize = 1000;

    pub fn record_history(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        self.history.push(line.to_string());
        if self.history.len() > Self::MAX_HISTORY {
            let overflow = self.history.len() - Self::MAX_HISTORY;
            self.history.drain(0..overflow);
        }
    }

    pub fn cwd_path(&self) -> String {
        self.vfs.path_of(self.cwd)
    }

    pub fn prompt(&self) -> String {
        let sigil = if self.uid == ROOT_UID { '#' } else { '$' };
        let cwd = self.cwd_path();
        let home = self.vfs.path_of(self.home);
        let display = if cwd == home {
            "~".to_string()
        } else if let Some(rest) = cwd.strip_prefix(&format!("{home}/")) {
            format!("~/{rest}")
        } else {
            cwd
        };
        format!("{}@{}:{}{} ", self.username, self.hostname, display, sigil)
    }

    pub fn parse_line(&mut self, line: &str) -> Vec<String> {
        let expanded = self.expand(line);
        parser::tokenize(&expanded)
    }

    pub fn switch_user(&mut self, user: &str) {
        let account = Account::named(user);
        let home = account.ensure_home(&mut self.vfs);

        let connection: Vec<(&str, String)> = CONNECTION_VARS
            .iter()
            .filter_map(|key| self.env.get(key).map(|value| (*key, value.to_string())))
            .collect();
        self.env = Env::login(account.name, &account.home, &self.hostname);
        for (key, value) in connection {
            self.env.set(key, &value);
        }
        self.username = account.name.to_string();
        self.uid = account.uid;
        self.gid = account.gid;
        self.cwd = home;
        self.home = home;
        self.prev_cwd = home;
    }
}

struct Account<'a> {
    name: &'a str,
    uid: u32,
    gid: u32,
    home: String,
}

impl<'a> Account<'a> {
    fn named(username: &'a str) -> Self {
        let name = if username.is_empty() {
            ROOT_USER
        } else {
            username
        };
        if name == ROOT_USER {
            return Self {
                name,
                uid: ROOT_UID,
                gid: ROOT_UID,
                home: ROOT_HOME.to_string(),
            };
        }
        Self {
            name,
            uid: REGULAR_UID,
            gid: REGULAR_UID,
            home: format!("/home/{name}"),
        }
    }

    fn ensure_home(&self, vfs: &mut Vfs) -> NodeId {
        if let Some(id) = vfs.resolve(vfs.root(), &self.home) {
            return id;
        }
        let (uid, gid) = (self.uid, self.gid);
        let Some(home) = vfs.mkdir_p(&self.home, HOME_DIR_MODE, uid, gid) else {
            return vfs.root();
        };
        vfs.add_file(
            home,
            ".bashrc",
            &b"# ~/.bashrc\n"[..],
            REGULAR_FILE_MODE,
            uid,
            gid,
        );
        vfs.add_file(
            home,
            ".profile",
            &b"# ~/.profile\n"[..],
            REGULAR_FILE_MODE,
            uid,
            gid,
        );
        home
    }
}

fn push_capped(buf: &mut String, text: &str) {
    buf.push_str(text);
    commands::truncate_stream(buf, commands::MAX_COMMAND_OUTPUT_BYTES);
}

fn floor_char_boundary(text: &str, index: usize) -> usize {
    if index >= text.len() {
        return text.len();
    }
    (0..=index)
        .rev()
        .find(|&i| text.is_char_boundary(i))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_starts_in_root_home() {
        let shell = Shell::new("root", "debian");
        assert_eq!(shell.cwd_path(), "/root");
        assert_eq!(shell.uid, 0);
        assert_eq!(shell.prompt(), "root@debian:~# ");
    }

    #[test]
    fn unknown_user_gets_created_home() {
        let shell = Shell::new("attacker", "debian");
        assert_eq!(shell.cwd_path(), "/home/attacker");
        assert_eq!(shell.uid, 1000);
        assert_eq!(shell.prompt(), "attacker@debian:~$ ");
    }

    #[test]
    fn prompt_abbreviates_paths_under_home() {
        let mut shell = Shell::new("root", "debian");

        shell.cwd = shell.vfs.resolve(shell.vfs.root(), "/etc").unwrap();
        assert_eq!(shell.prompt(), "root@debian:/etc# ");
    }

    #[test]
    fn parse_line_expands_variables() {
        let mut shell = Shell::new("root", "debian");
        shell.last_status = 7;
        assert_eq!(shell.parse_line("echo $USER"), vec!["echo", "root"]);
        assert_eq!(shell.parse_line("echo ${HOME}"), vec!["echo", "/root"]);
        assert_eq!(shell.parse_line("echo $?"), vec!["echo", "7"]);
        assert_eq!(shell.parse_line("echo $$"), vec!["echo", "1337"]);
        assert_eq!(shell.parse_line("echo $#"), vec!["echo", "0"]);
        assert_eq!(shell.parse_line("echo $0"), vec!["echo", "-bash"]);
        assert_eq!(shell.parse_line("echo $1 $2"), vec!["echo"]);
        assert_eq!(
            shell.parse_line("echo ${#} ${0} ${1}"),
            vec!["echo", "0", "-bash"]
        );

        assert_eq!(shell.parse_line("echo $NOPE end"), vec!["echo", "end"]);
    }

    #[test]
    fn single_quotes_suppress_expansion() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.parse_line("echo '$USER'"), vec!["echo", "$USER"]);
    }

    #[test]
    fn double_quotes_expand_and_hold_a_single_quote() {
        let mut shell = Shell::new("root", "debian");

        assert_eq!(
            shell.parse_line(r#"echo "it's $USER""#),
            vec!["echo", "it's root"]
        );
        assert_eq!(shell.execute(r#"echo "it's $USER""#).text, "it's root\n");
    }

    #[test]
    fn a_backslash_protects_the_dollar_it_precedes() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.parse_line(r"echo \$USER"), vec!["echo", "$USER"]);
        assert_eq!(shell.parse_line(r#"echo "\$USER""#), vec!["echo", "$USER"]);

        assert_eq!(shell.parse_line(r"echo \\$USER"), vec!["echo", r"\root"]);
    }

    #[test]
    fn an_expanded_value_is_data_not_syntax() {
        let mut shell = Shell::new("root", "debian");
        shell.execute(r#"export Q="a'b""#);
        shell.execute(r#"export D='a"b'"#);
        shell.execute(r"export B='a\b'");
        shell.execute("export S='a  b'");

        assert_eq!(shell.execute("echo $Q").text, "a'b\n");
        assert_eq!(shell.execute(r#"echo "$D""#).text, "a\"b\n");
        assert_eq!(shell.execute("echo $B").text, "a\\b\n");

        assert_eq!(shell.execute("echo $D tail").text, "a\"b tail\n");

        assert_eq!(shell.parse_line("echo $S"), vec!["echo", "a", "b"]);
        assert_eq!(shell.parse_line(r#"echo "$S""#), vec!["echo", "a  b"]);
    }

    #[test]
    fn command_substitution_runs_the_body() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.execute("echo $(whoami)").text, "root\n");
        assert_eq!(shell.execute("echo `whoami`").text, "root\n");

        assert_eq!(shell.execute("echo $(cd /tmp; pwd)").text, "/tmp\n");
        assert_eq!(shell.execute("echo $(echo a b c | wc -w)").text, "3\n");

        assert_eq!(shell.execute(r#"echo "[$(echo hi)]""#).text, "[hi]\n");
        assert_eq!(
            shell.execute(r#"echo "[$(echo one; echo two)]""#).text,
            "[one\ntwo]\n"
        );

        assert_eq!(shell.execute("echo $(echo $(whoami))").text, "root\n");

        assert_eq!(shell.execute("echo '$(whoami)'").text, "$(whoami)\n");
        assert_eq!(shell.execute(r"echo \$(whoami)").text, "$(whoami)\n");
        assert_eq!(shell.execute("echo '`whoami`'").text, "`whoami`\n");
    }

    #[test]
    fn substitution_output_is_data_not_syntax() {
        let mut shell = Shell::new("root", "debian");

        assert_eq!(
            shell.execute("echo $(echo 'a; touch /tmp/pwned')").text,
            "a; touch /tmp/pwned\n"
        );
        assert!(shell.vfs.resolve(shell.vfs.root(), "/tmp/pwned").is_none());

        assert_eq!(
            shell.execute("echo $(echo 'a > /tmp/out | b')").text,
            "a > /tmp/out | b\n"
        );
        assert!(shell.vfs.resolve(shell.vfs.root(), "/tmp/out").is_none());
        assert_eq!(shell.execute(r#"echo $(echo "it's")"#).text, "it's\n");
        assert_eq!(shell.execute("echo $(echo '$USER')").text, "$USER\n");

        shell.execute("echo before > /tmp/f");
        shell.execute("echo $(cat /tmp/f) > /tmp/f");
        assert_eq!(shell.execute("cat /tmp/f").text, "before\n");

        assert_eq!(
            shell.parse_line("echo $(echo 'a  b')"),
            vec!["echo", "a", "b"]
        );
        assert_eq!(
            shell.parse_line(r#"echo "$(echo 'a  b')""#),
            vec!["echo", "a  b"]
        );
    }

    #[test]
    fn a_substitution_is_a_subshell_not_the_session() {
        let mut shell = Shell::new("root", "debian");

        let out = shell.execute("echo $(exit)");
        assert!(!out.exit);
        assert_eq!(out.text, "\n");

        shell.execute("echo $(cd /tmp; export MARK=1; touch /tmp/left-behind)");
        assert_eq!(shell.cwd_path(), "/root");
        assert_eq!(shell.execute("echo $MARK").text, "\n");
        assert!(shell
            .vfs
            .resolve(shell.vfs.root(), "/tmp/left-behind")
            .is_some());

        assert_eq!(shell.execute("echo $(false)").status, 0);
        assert_eq!(shell.execute("echo $?").text, "0\n");
    }

    #[test]
    fn a_substitution_keeps_the_captures_around_it() {
        let mut shell = Shell::new("root", "debian");
        shell.execute("wget http://example.com/one -O /tmp/one; echo $(wget http://example.com/two -O /tmp/two)");
        let urls: Vec<&str> = shell
            .captures
            .iter()
            .filter_map(|capture| match capture {
                Capture::Download { url, .. } => Some(url.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            urls,
            vec!["http://example.com/one", "http://example.com/two"]
        );
    }

    #[test]
    fn arithmetic_expansion_evaluates_the_expression() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.execute("echo $((2+3*4))").text, "14\n");
        assert_eq!(shell.execute("echo $(( (2+3)*4 ))").text, "20\n");

        assert_eq!(shell.execute("echo $((3>2))").text, "1\n");
        assert!(shell.vfs.resolve(shell.vfs.root(), "/root/2").is_none());

        shell.execute("export N=20");
        assert_eq!(shell.execute("echo $((N+$N))").text, "40\n");
        assert_eq!(shell.execute("echo $((1+$(echo 2)))").text, "3\n");

        assert_eq!(shell.execute("echo '$((1+1))'").text, "$((1+1))\n");
    }

    #[test]
    fn escapes_in_a_value_reach_echo_e() {
        let mut shell = Shell::new("root", "debian");
        shell.execute(r"export T='a\tb'");

        assert_eq!(shell.execute("echo -e $T").text, "a\tb\n");
        assert_eq!(shell.execute("echo $T").text, "a\\tb\n");
    }

    #[test]
    fn execute_reports_command_status() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.execute("true").status, 0);
        assert_eq!(shell.execute("false").status, 1);
        assert_eq!(shell.execute("missing-command").status, 127);

        let mut fresh = Shell::new("root", "debian");
        let exit_default = fresh.execute("exit");
        assert_eq!(exit_default.status, 0);
        assert!(exit_default.exit);
        assert_eq!(exit_default.text, "logout\n");

        let exit_code = shell.execute("exit 42");
        assert_eq!(exit_code.status, 42);
        assert!(exit_code.exit);
        assert_eq!(exit_code.text, "logout\n");

        let exit_chained = shell.execute("false; exit");
        assert_eq!(exit_chained.status, 1);
        assert!(exit_chained.exit);
        assert_eq!(exit_chained.text, "logout\n");

        let exit_nan = shell.execute("exit abc");
        assert_eq!(exit_nan.status, 2);
        assert!(exit_nan.exit);
        assert!(exit_nan
            .text
            .contains("-bash: exit: abc: numeric argument required\nlogout\n"));

        let exit_too_many = shell.execute("exit 1 2");
        assert_eq!(exit_too_many.status, 1);
        assert!(!exit_too_many.exit);
        assert_eq!(exit_too_many.text, "-bash: exit: too many arguments\n");
    }

    #[test]
    fn parse_line_honours_quoting_and_escapes() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(
            shell.parse_line(r#"echo "a b"  c"#),
            vec!["echo", "a b", "c"]
        );
        assert_eq!(shell.parse_line(r"echo a\ b"), vec!["echo", "a b"]);
        assert!(shell.parse_line("   ").is_empty());
    }

    #[test]
    fn chained_commands_run_in_order_and_honour_status() {
        let mut shell = Shell::new("root", "debian");

        let out = shell.execute("echo one; echo two; echo three");
        assert_eq!(out.text, "one\ntwo\nthree\n");
        assert_eq!(out.status, 0);

        assert_eq!(shell.execute("false && echo nope").text, "");
        assert_eq!(shell.execute("false || echo yes").text, "yes\n");
        assert_eq!(shell.execute("true && echo yes").text, "yes\n");
        assert_eq!(shell.execute("true || echo nope").text, "");

        assert_eq!(shell.execute("false && echo nope; echo $?").text, "1\n");

        let out = shell.execute("cd /tmp; mkdir -p a/b; find /tmp -type d");
        assert_eq!(out.text, "/tmp\n/tmp/a\n/tmp/a/b\n");

        assert_eq!(shell.execute("echo 'a; b'").text, "a; b\n");
        assert_eq!(shell.execute(r"echo a\;b").text, "a;b\n");

        shell.execute("export EVIL='x; echo pwned'");
        assert_eq!(shell.execute("echo $EVIL").text, "x; echo pwned\n");
    }

    #[test]
    fn comments_are_not_commands() {
        let mut shell = Shell::new("root", "debian");

        shell.execute("false");
        let out = shell.execute("# just looking");
        assert_eq!(out.text, "");
        assert_eq!(shell.execute("echo $?").text, "1\n");

        assert_eq!(shell.execute("echo a # b").text, "a\n");
        assert_eq!(shell.execute("echo a # b; echo c").text, "a\n");
        assert_eq!(shell.execute("echo a; # b").text, "a\n");

        assert_eq!(shell.execute("echo a#b").text, "a#b\n");
        assert_eq!(shell.execute("echo '#!/bin/sh' > /tmp/x").text, "");
        assert_eq!(shell.execute("cat /tmp/x").text, "#!/bin/sh\n");
        assert_eq!(shell.execute(r##"echo "# kept""##).text, "# kept\n");
        assert_eq!(shell.execute(r"echo \# kept").text, "# kept\n");

        shell.execute("export C='# x'");
        assert_eq!(shell.execute("echo $C").text, "# x\n");
    }

    #[test]
    fn pipelines_feed_stdin_to_the_next_stage() {
        let mut shell = Shell::new("root", "debian");

        assert_eq!(
            shell.execute("cat /etc/passwd | grep sshd").text,
            "sshd:x:100:65534::/run/sshd:/usr/sbin/nologin\n"
        );
        assert_eq!(shell.execute("cat /etc/passwd | wc -l").text, "15\n");
        assert_eq!(
            shell.execute("cat /etc/passwd | head -n 1").text,
            "root:x:0:0:root:/root:/bin/bash\n"
        );
        assert_eq!(
            shell.execute("cat /etc/passwd | grep bash | wc -l").text,
            "2\n"
        );

        shell.execute("cat /etc/passwd | grep nosuchuser");
        assert_eq!(shell.last_status, 1);

        assert_eq!(shell.execute("cat /etc/passwd | whoami").text, "root\n");

        assert_eq!(
            shell.execute("ls /usr/bin | head -n 2").text,
            "[\naddpart\n"
        );
        assert!(shell.execute("ls /usr/bin").text.lines().count() == 1);

        assert_eq!(shell.execute("echo 'a | b'").text, "a | b\n");
        assert_eq!(shell.execute("false || echo fallback").text, "fallback\n");

        assert_eq!(
            shell
                .execute("cd /tmp && cat /etc/passwd | grep -c bash")
                .text,
            "2\n"
        );
    }

    #[test]
    fn redirection_writes_output_into_the_filesystem() {
        let mut shell = Shell::new("root", "debian");

        let out = shell.execute("echo hello > /tmp/f");
        assert_eq!(out.text, "");
        assert_eq!(out.status, 0);
        assert_eq!(shell.execute("cat /tmp/f").text, "hello\n");

        shell.execute("echo second >> /tmp/f");
        assert_eq!(shell.execute("cat /tmp/f").text, "hello\nsecond\n");
        shell.execute("echo third > /tmp/f");
        assert_eq!(shell.execute("cat /tmp/f").text, "third\n");

        shell.execute("mkdir -p /tmp/d && touch /tmp/d/a /tmp/d/b");
        shell.execute("ls /tmp/d > /tmp/names");
        assert_eq!(shell.execute("cat /tmp/names").text, "a\nb\n");

        shell.execute("echo home > $HOME/f");
        assert_eq!(shell.execute("cat /root/f").text, "home\n");

        shell.execute("export EVIL='x > /tmp/pwned'");
        assert_eq!(shell.execute("echo $EVIL").text, "x > /tmp/pwned\n");
        assert!(shell
            .execute("cat /tmp/pwned")
            .text
            .contains("No such file or directory"));

        shell.execute("cat /etc/passwd | grep bash > /tmp/shells");
        assert!(shell
            .execute("wc -l /tmp/shells")
            .text
            .contains("2 /tmp/shells"));

        shell.execute("> /tmp/f");
        assert_eq!(shell.execute("cat /tmp/f").text, "");
    }

    fn feed(shell: &mut Shell, lines: &[&str]) -> Output {
        let mut last = Output::default();
        for line in lines {
            assert!(
                shell.pending.is_some(),
                "shell stopped collecting at {line}"
            );
            last = shell.resume(line);
        }
        assert!(shell.pending.is_none(), "body never ended");
        last
    }

    #[test]
    fn a_heredoc_collects_its_body_and_feeds_it_as_stdin() {
        let mut shell = Shell::new("root", "debian");

        let opened = shell.execute("cat << EOF");
        assert_eq!(opened.text, "");
        assert!(shell.pending.is_some(), "no here-document was opened");

        assert_eq!(
            feed(&mut shell, &["one", "two", "EOF"]).stdout,
            "one\ntwo\n"
        );

        assert_eq!(
            shell
                .heredoc_log
                .take()
                .expect("nothing left for the capture"),
            "cat << EOF\none\ntwo\nEOF"
        );

        shell.execute("cat << EOF > /tmp/f");
        feed(&mut shell, &["written", "EOF"]);
        assert_eq!(shell.execute("cat /tmp/f").stdout, "written\n");

        shell.execute("cat << EOF | wc -l");
        assert_eq!(feed(&mut shell, &["a", "b", "c", "EOF"]).stdout, "3\n");

        shell.execute("export NAME=world");
        shell.execute("cat << EOF");
        assert_eq!(feed(&mut shell, &["hi $NAME", "EOF"]).stdout, "hi world\n");
        shell.execute("cat << 'EOF'");
        assert_eq!(feed(&mut shell, &["hi $NAME", "EOF"]).stdout, "hi $NAME\n");

        shell.execute("cat << 'EOF'");
        assert_eq!(
            feed(&mut shell, &[r#"a "b" 'c' \d"#, "EOF"]).stdout,
            "a \"b\" 'c' \\d\n"
        );

        shell.execute("cat <<- EOF");
        assert_eq!(
            feed(&mut shell, &["\tindented", "\tEOF"]).stdout,
            "indented\n"
        );

        shell.execute("cat << EOF");
        assert_eq!(
            feed(&mut shell, &["EOF and more", "EOF"]).stdout,
            "EOF and more\n"
        );
    }

    #[test]
    fn a_heredoc_operator_is_only_one_where_bash_sees_one() {
        let mut shell = Shell::new("root", "debian");

        shell.execute("echo $((1 << 4))");
        assert!(shell.pending.is_none(), "a shift opened a here-document");

        assert_eq!(shell.execute("echo 'a << b'").stdout, "a << b\n");
        assert!(shell.pending.is_none());
        shell.execute("export EVIL='x << EOF'");
        assert_eq!(shell.execute("echo $EVIL").stdout, "x << EOF\n");
        assert!(shell.pending.is_none());

        shell.execute("cat << EOF");
        shell.resume("half a body");
        let out = shell.finish_heredoc_at_eof().expect("a document was open");
        assert_eq!(out.stdout, "half a body\n");
        assert!(
            out.stderr
                .contains("here-document delimited by end-of-file"),
            "missing warning: {:?}",
            out.stderr
        );
        assert!(shell.pending.is_none());
        assert!(shell.finish_heredoc_at_eof().is_none(), "closed twice");
    }

    #[test]
    fn the_two_streams_stay_apart() {
        let mut shell = Shell::new("root", "debian");

        let out = shell.execute("nosuchcmd");
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, "-bash: nosuchcmd: command not found\n");
        assert_eq!(out.status, 127);
        assert_eq!(shell.execute("nosuchcmd 2> /dev/null").stderr, "");

        shell.execute("mkdir -p /tmp/d && touch /tmp/d/a");
        let out = shell.execute("ls /tmp/d /nope");
        assert_eq!(out.stdout, "/tmp/d:\na\n");
        assert_eq!(
            out.stderr,
            "ls: cannot access '/nope': No such file or directory\n"
        );

        assert_eq!(out.text, format!("{}{}", out.stderr, out.stdout));

        let out = shell.execute("echo $(ls /nope)");
        assert_eq!(out.stdout, "\n");
        assert_eq!(
            out.stderr,
            "ls: cannot access '/nope': No such file or directory\n"
        );

        let out = shell.execute("echo $(ls /nope) 2> /dev/null");
        assert!(out.stderr.contains("No such file or directory"));

        let out = shell.execute("cat /nope | wc -l");
        assert_eq!(out.stdout, "0\n");
        assert_eq!(out.stderr, "cat: /nope: No such file or directory\n");

        let out = shell.execute("ls /nope 2>&1");
        assert_eq!(
            out.stdout,
            "ls: cannot access '/nope': No such file or directory\n"
        );
        assert_eq!(out.stderr, "");
        assert_eq!(shell.execute("ls /nope 2>&1 | wc -l").stdout, "1\n");

        let out = shell.execute("echo oops >&2");
        assert_eq!(out.stdout, "");
        assert_eq!(out.stderr, "oops\n");
        let out = shell.execute("echo fine >&1");
        assert_eq!(out.stdout, "fine\n");
        assert_eq!(out.stderr, "");

        shell.execute("ls /nope 2>&1 > /tmp/only-out");
        let out = shell.execute("ls /nope 2>&1 > /tmp/only-out");
        assert!(out.stdout.contains("No such file or directory"));
        assert_eq!(shell.execute("cat /tmp/only-out").stdout, "");
    }

    #[test]
    fn redirection_routes_errors_and_reports_refused_targets() {
        let mut shell = Shell::new("root", "debian");

        let out = shell.execute("ls /nope > /tmp/out");
        assert!(out.text.contains("No such file or directory"));
        assert_eq!(out.status, 2);
        assert_eq!(shell.execute("cat /tmp/out").text, "");

        assert_eq!(shell.execute("ls /nope 2> /tmp/err").text, "");
        assert!(shell
            .execute("cat /tmp/err")
            .text
            .contains("No such file or directory"));
        assert_eq!(shell.execute("ls /nope &> /tmp/both").text, "");
        assert_eq!(shell.execute("echo ok &> /tmp/both").text, "");
        assert_eq!(shell.execute("cat /tmp/both").text, "ok\n");

        assert_eq!(shell.execute("ls /nope > /tmp/all 2>&1").text, "");
        assert!(shell
            .execute("cat /tmp/all")
            .text
            .contains("No such file or directory"));

        shell.execute("mkdir -p /tmp/d2 && touch /tmp/d2/a");
        shell.execute("ls /nope /tmp/d2 > /tmp/mix 2>&1");
        assert_eq!(
            shell.execute("cat /tmp/mix").text,
            "ls: cannot access '/nope': No such file or directory\n/tmp/d2:\na\n"
        );
        assert!(shell
            .execute("ls /nope 2>&1")
            .text
            .contains("No such file or directory"));

        assert_eq!(shell.execute("echo noise > /dev/null").text, "");
        assert_eq!(shell.execute("cat /dev/null").text, "");
        shell.execute("cd /dev && echo noise > null");
        assert_eq!(shell.execute("cat /dev/null").text, "");
        shell.execute("cd /tmp");

        let out = shell.execute("echo x > /nope/f");
        assert_eq!(out.text, "-bash: /nope/f: No such file or directory\n");
        assert_eq!(out.status, 1);
        assert_eq!(
            shell.execute("echo x > /tmp").text,
            "-bash: /tmp: Is a directory\n"
        );

        assert!(shell.execute("mkdir /tmp/unreached > /nope/f").status == 1);
        assert!(shell
            .execute("ls /tmp/unreached")
            .text
            .contains("No such file or directory"));

        let mut user = Shell::new("attacker", "debian");
        let out = user.execute("echo x > /root/f");
        assert_eq!(out.text, "-bash: /root/f: Permission denied\n");
        assert_eq!(out.status, 1);

        assert_eq!(
            shell.execute("echo x > $UNSET").text,
            "-bash: $UNSET: ambiguous redirect\n"
        );
        shell.execute("export TWO='a b'");
        assert_eq!(
            shell.execute("echo x > $TWO").text,
            "-bash: $TWO: ambiguous redirect\n"
        );
        assert!(!shell.execute("ls -a /").text.contains('$'));
    }

    #[test]
    fn a_redirect_refused_by_the_vfs_cap_is_reported() {
        let mut shell = Shell::new("root", "debian");
        shell.execute("cd /tmp");

        let big = "A".repeat(7 * 1024 * 1024 + 512 * 1024);
        {
            let cwd = shell.cwd;
            shell
                .vfs
                .add_file(cwd, "big", big.into_bytes(), 0o644, 0, 0);
        }
        assert!(
            shell.execute("cat /tmp/big").text.len() > commands::MAX_COMMAND_OUTPUT_BYTES / 2,
            "the fill file was itself refused, so the cap is never reached"
        );

        let out = shell.execute("cat /tmp/big > /tmp/copy");
        assert!(
            out.text.contains("No space left on device"),
            "silently dropped the write: {:?}",
            out.text
        );
        assert_ne!(out.status, 0);
    }

    #[test]
    fn a_chained_line_is_output_bounded_as_a_whole() {
        let mut shell = Shell::new("root", "debian");
        let big = "A".repeat(200_000);
        shell.execute("cd /tmp");
        {
            let cwd = shell.cwd;
            shell
                .vfs
                .add_file(cwd, "big", big.into_bytes(), 0o644, 0, 0);
        }

        let line = std::iter::repeat_n("cat /tmp/big", 40)
            .collect::<Vec<_>>()
            .join("; ");
        let out = shell.execute(&line);

        assert!(
            out.text.len() <= commands::MAX_COMMAND_OUTPUT_BYTES + 64,
            "chained line produced {} bytes",
            out.text.len()
        );
        assert!(out.text.ends_with("... (output truncated)\n"));
    }

    #[test]
    fn su_rebuilds_the_login_env_but_keeps_the_connection_vars() {
        let mut shell = Shell::new("root", "debian");
        shell
            .env
            .set("SSH_CONNECTION", "10.0.0.5 54321 10.0.0.9 22");
        shell.env.set("SSH_TTY", "/dev/pts/0");

        shell.switch_user("user");

        assert_eq!(shell.env.get("USER"), Some("user"));
        assert_eq!(shell.env.get("HOME"), Some("/home/user"));
        assert_eq!(
            shell.env.get("SSH_CONNECTION"),
            Some("10.0.0.5 54321 10.0.0.9 22")
        );
        assert_eq!(shell.env.get("SSH_TTY"), Some("/dev/pts/0"));
    }

    #[test]
    fn history_skips_blank_and_is_bounded() {
        let mut shell = Shell::new("root", "debian");
        shell.record_history("   ");
        assert!(shell.history.is_empty());
        for i in 0..(Shell::MAX_HISTORY + 50) {
            shell.record_history(&format!("cmd{i}"));
        }
        assert_eq!(shell.history.len(), Shell::MAX_HISTORY);
        assert_eq!(shell.history.last().unwrap(), "cmd1049");
    }
}
