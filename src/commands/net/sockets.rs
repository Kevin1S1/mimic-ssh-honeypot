use crate::commands::CommandResult;
use crate::shell::Shell;

const SSHD_LISTENER: &str = "604/sshd: /usr/sb";

fn flag_letters(args: &[String]) -> String {
    args.iter()
        .filter(|a| a.starts_with('-'))
        .map(String::as_str)
        .collect()
}

pub fn netstat(_shell: &Shell, args: &[String]) -> CommandResult {
    let flags = flag_letters(args);
    let listening = flags.contains('l');
    let numeric = flags.contains('n');
    let show_prog = flags.contains('p');

    let mut out = String::from("Active Internet connections (");
    out.push_str(if listening {
        "only servers)\n"
    } else {
        "w/o servers)\n"
    });
    out.push_str("Proto Recv-Q Send-Q Local Address           Foreign Address         State      ");
    out.push_str(if show_prog {
        "PID/Program name\n"
    } else {
        "\n"
    });

    let prog = |p: &'static str| if show_prog { p } else { "" };
    let address = |numeric_form: &'static str, named_form: &'static str| {
        if numeric {
            numeric_form
        } else {
            named_form
        }
    };
    if listening {
        out.push_str(&format!(
            "tcp        0      0 {:<23} 0.0.0.0:*               LISTEN      {}\n",
            address("0.0.0.0:22", "0.0.0.0:ssh"),
            prog(SSHD_LISTENER)
        ));
        out.push_str(&format!(
            "tcp6       0      0 {:<23} :::*                    LISTEN      {}\n",
            address(":::22", ":::ssh"),
            prog(SSHD_LISTENER)
        ));
    } else {
        out.push_str(&format!(
            "tcp        0      0 {:<23} {:<23} ESTABLISHED {}\n",
            address("10.0.0.5:22", "debian:ssh"),
            "10.0.0.1:51394",
            prog("604/sshd: root@pt")
        ));
    }
    CommandResult::ok(out)
}

pub fn ss(_shell: &Shell, args: &[String]) -> CommandResult {
    let flags = flag_letters(args);
    let listening = flags.contains('l');
    let show_prog = flags.contains('p');

    let mut out =
        String::from("State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port   ");
    out.push_str(if show_prog { "Process\n" } else { "\n" });

    let proc_col = |p: &'static str| if show_prog { p } else { "" };
    if listening {
        out.push_str(&format!(
            "LISTEN   0        128              0.0.0.0:22             0.0.0.0:*          {}\n",
            proc_col("users:((\"sshd\",pid=604,fd=3))")
        ));
        out.push_str(&format!(
            "LISTEN   0        128                 [::]:22                [::]:*          {}\n",
            proc_col("users:((\"sshd\",pid=604,fd=4))")
        ));
    } else {
        out.push_str(&format!(
            "ESTAB    0        0               10.0.0.5:22           10.0.0.1:51394      {}\n",
            proc_col("users:((\"sshd\",pid=1340,fd=4))")
        ));
    }
    CommandResult::ok(out)
}
