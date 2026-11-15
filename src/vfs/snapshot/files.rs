pub(super) const SSHD_CONFIG: &str =
    "# This is the sshd server system-wide configuration file.  See\n\
# sshd_config(5) for more information.\n\
\n\
Include /etc/ssh/sshd_config.d/*.conf\n\
\n\
#Port 22\n\
#AddressFamily any\n\
#ListenAddress 0.0.0.0\n\
#ListenAddress ::\n\
\n\
#HostKey /etc/ssh/ssh_host_rsa_key\n\
#HostKey /etc/ssh/ssh_host_ecdsa_key\n\
#HostKey /etc/ssh/ssh_host_ed25519_key\n\
\n\
# Ciphers and keying\n\
#RekeyLimit default none\n\
\n\
# Logging\n\
#SyslogFacility AUTH\n\
#LogLevel INFO\n\
\n\
# Authentication:\n\
\n\
#LoginGraceTime 2m\n\
#PermitRootLogin prohibit-password\n\
#StrictModes yes\n\
MaxAuthTries 6\n\
#MaxSessions 10\n\
\n\
#PubkeyAuthentication yes\n\
\n\
# Expect .ssh/authorized_keys2 to be disregarded by default in future.\n\
#AuthorizedKeysFile\t.ssh/authorized_keys .ssh/authorized_keys2\n\
\n\
#AuthorizedPrincipalsFile none\n\
\n\
# To disable tunneled clear text passwords, change to no here!\n\
#PasswordAuthentication yes\n\
#PermitEmptyPasswords no\n\
\n\
# Change to yes to enable challenge-response passwords (beware issues with\n\
# some PAM modules and threads)\n\
KbdInteractiveAuthentication no\n\
\n\
UsePAM yes\n\
\n\
#AllowAgentForwarding yes\n\
#AllowTcpForwarding yes\n\
#GatewayPorts no\n\
X11Forwarding yes\n\
#X11DisplayOffset 10\n\
#PrintMotd yes\n\
#PrintLastLog yes\n\
#TCPKeepAlive yes\n\
#PermitUserEnvironment no\n\
#Compression delayed\n\
#ClientAliveInterval 0\n\
#ClientAliveCountMax 3\n\
#UseDNS no\n\
#PidFile /run/sshd.pid\n\
#MaxStartups 10:30:100\n\
#PermitTunnel no\n\
#Banner none\n\
\n\
# Allow client to pass locale environment variables\n\
AcceptEnv LANG LC_*\n\
\n\
# override default of no subsystems\n\
Subsystem\tsftp\t/usr/lib/openssh/sftp-server\n";

pub(super) const SSH_CONFIG: &str =
    "# This is the ssh client system-wide configuration file.  See\n\
# ssh_config(5) for more information.\n\
\n\
Include /etc/ssh/ssh_config.d/*.conf\n\
\n\
Host *\n\
\x20   SendEnv LANG LC_*\n\
\x20   HashKnownHosts yes\n\
\x20   GSSAPIAuthentication yes\n";

pub(super) const SOURCES_LIST: &str = "deb http://deb.debian.org/debian bookworm main\n\
deb-src http://deb.debian.org/debian bookworm main\n\
\n\
deb http://deb.debian.org/debian-security/ bookworm-security main\n\
deb-src http://deb.debian.org/debian-security/ bookworm-security main\n\
\n\
deb http://deb.debian.org/debian bookworm-updates main\n\
deb-src http://deb.debian.org/debian bookworm-updates main\n";

pub(super) const OS_RELEASE: &str = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n\
NAME=\"Debian GNU/Linux\"\n\
VERSION_ID=\"12\"\n\
VERSION=\"12 (bookworm)\"\n\
VERSION_CODENAME=bookworm\n\
ID=debian\n\
HOME_URL=\"https://www.debian.org/\"\n\
SUPPORT_URL=\"https://www.debian.org/support\"\n\
BUG_REPORT_URL=\"https://bugs.debian.org/\"\n";

pub(super) const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
sys:x:3:3:sys:/dev:/usr/sbin/nologin\n\
sync:x:4:65534:sync:/bin:/bin/sync\n\
games:x:5:60:games:/usr/games:/usr/sbin/nologin\n\
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n\
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n\
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n\
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n\
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n\
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
sshd:x:100:65534::/run/sshd:/usr/sbin/nologin\n\
user:x:1000:1000:user,,,:/home/user:/bin/bash\n";

pub(super) const GROUP: &str = "root:x:0:\n\
daemon:x:1:\n\
bin:x:2:\n\
sys:x:3:\n\
adm:x:4:\n\
tty:x:5:\n\
disk:x:6:\n\
sudo:x:27:user\n\
www-data:x:33:\n\
ssh:x:114:\n\
user:x:1000:\n";

pub(super) const SHADOW: &str = "root:!:19000:0:99999:7:::\n\
daemon:*:19000:0:99999:7:::\n\
sshd:!:19000:0:99999:7:::\n\
user:$6$rounds=656000$D1G7H204ckii$Abjn5s.euB1Z/rC2tdRk8fQxF5ucdtUgVpg.H.tPzMNktyVxhqoAclDrdXCw29WpcY68HNAlSzrJwXX1kX/PvS:19000:0:99999:7:::\n";

pub(super) const BASHRC: &str = "# ~/.bashrc: executed by bash(1) for non-login shells.\n\
\n\
case $- in\n\
    *i*) ;;\n\
      *) return;;\n\
esac\n\
\n\
HISTCONTROL=ignoreboth\n\
HISTSIZE=1000\n\
HISTFILESIZE=2000\n\
shopt -s checkwinsize\n\
\n\
if [ -x /usr/bin/dircolors ]; then\n\
    alias ls='ls --color=auto'\n\
    alias grep='grep --color=auto'\n\
fi\n\
\n\
alias ll='ls -alF'\n\
alias la='ls -A'\n\
alias l='ls -CF'\n";

pub(super) const PROFILE: &str =
    "# ~/.profile: executed by the command interpreter for login shells.\n\
\n\
if [ -n \"$BASH_VERSION\" ]; then\n\
    if [ -f \"$HOME/.bashrc\" ]; then\n\
\t. \"$HOME/.bashrc\"\n\
    fi\n\
fi\n\
\n\
if [ -d \"$HOME/bin\" ] ; then\n\
    PATH=\"$HOME/bin:$PATH\"\n\
fi\n";

const HOSTS_TAIL: &str = "\n\
::1     localhost ip6-localhost ip6-loopback\n\
ff02::1 ip6-allnodes\n\
ff02::2 ip6-allrouters\n";

pub(super) fn hosts_file(hostname: &str) -> String {
    format!("127.0.0.1\tlocalhost\n127.0.1.1\t{hostname}\n{HOSTS_TAIL}")
}
