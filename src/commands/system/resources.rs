use crate::commands::CommandResult;
use crate::shell::Shell;

pub fn free(shell: &Shell, args: &[String]) -> CommandResult {
    let human = args.iter().any(|a| a == "-h" || a == "--human");
    let mega = args.iter().any(|a| a == "-m");
    let giga = args.iter().any(|a| a == "-g");

    let mem = shell.persona.memory();

    let fmt = |kb: u64| -> String {
        if human {
            human_kib(kb)
        } else if mega {
            (kb / 1024).to_string()
        } else if giga {
            (kb / 1024 / 1024).to_string()
        } else {
            kb.to_string()
        }
    };

    let mut out = String::new();
    out.push_str(
        "               total        used        free      shared  buff/cache   available\n",
    );
    out.push_str(&format!(
        "Mem:    {:>12} {:>11} {:>11} {:>11} {:>11} {:>11}\n",
        fmt(mem.total),
        fmt(mem.used),
        fmt(mem.free),
        fmt(mem.shared),
        fmt(mem.buff_cache),
        fmt(mem.available)
    ));
    out.push_str(&format!(
        "Swap:   {:>12} {:>11} {:>11}\n",
        fmt(0),
        fmt(0),
        fmt(0)
    ));
    CommandResult::ok(out)
}

fn human_kib(kb: u64) -> String {
    let bytes = kb as f64 * 1024.0;
    const UNITS: [&str; 5] = ["B", "Ki", "Mi", "Gi", "Ti"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{}B", value as u64)
    } else if value < 10.0 {
        format!("{value:.1}{}", UNITS[unit])
    } else {
        format!("{value:.0}{}", UNITS[unit])
    }
}

const SHM_RAM_DIVISOR: u64 = 2;

const RUN_RAM_DIVISOR: u64 = 10;

const UDEV_RESERVED_KB: u64 = 5270;

const RUN_USED_KB: u64 = 960;

const ROOT_USED_PERCENT: u64 = 16;

const ROOT_RESERVED_PERCENT: u64 = 5;

pub fn df(shell: &Shell, args: &[String]) -> CommandResult {
    let human = args.iter().any(|a| a == "-h" || a == "--human-readable");

    let ram = shell.persona.memory().total;
    let disk = shell.persona.disk_total_kb;
    let shm = ram / SHM_RAM_DIVISOR;
    let udev = shm - UDEV_RESERVED_KB;
    let run = ram / RUN_RAM_DIVISOR;
    let used = disk * ROOT_USED_PERCENT / 100;
    let avail = disk - used - disk * ROOT_RESERVED_PERCENT / 100;
    let pct = (used * 100).div_ceil(disk.max(1));
    let uid = shell.uid;

    let out = if human {
        format!(
            "Filesystem      Size  Used Avail Use% Mounted on\n\
             udev            {udev:>4}     0  {udev:>4}   0% /dev\n\
             tmpfs           {run:>4}  960K  {run:>4}   1% /run\n\
             /dev/sda1       {disk:>4}  {used:>4}  {avail:>4}  {pct}% /\n\
             tmpfs           {shm:>4}     0  {shm:>4}   0% /dev/shm\n\
             tmpfs           5.0M     0  5.0M   0% /run/lock\n\
             tmpfs           {run:>4}     0  {run:>4}   0% /run/user/{uid}\n",
            udev = human_kib(udev),
            run = human_kib(run),
            shm = human_kib(shm),
            disk = human_kib(disk),
            used = human_kib(used),
            avail = human_kib(avail),
            pct = pct,
            uid = uid,
        )
    } else {
        format!(
            "Filesystem     1K-blocks    Used Available Use% Mounted on\n\
             udev          {udev:>10}       0  {udev:>8}   0% /dev\n\
             tmpfs         {run:>10} {RUN_USED_KB:>7}  {run_avail:>8}   1% /run\n\
             /dev/sda1     {disk:>10} {used:>7}  {avail:>8}  {pct}% /\n\
             tmpfs         {shm:>10}       0  {shm:>8}   0% /dev/shm\n\
             tmpfs               5120       0      5120   0% /run/lock\n\
             tmpfs         {run:>10}       0  {run:>8}   0% /run/user/{uid}\n",
            udev = udev,
            run = run,
            run_avail = run - RUN_USED_KB,
            disk = disk,
            used = used,
            avail = avail,
            pct = pct,
            shm = shm,
            uid = uid,
        )
    };
    CommandResult::ok(out)
}

pub fn mount(_shell: &Shell, _args: &[String]) -> CommandResult {
    let out = "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n\
        proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n\
        udev on /dev type devtmpfs (rw,nosuid,relatime,size=1015532k,nr_inodes=253883,mode=755)\n\
        devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)\n\
        tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=204120k,mode=755)\n\
        /dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\n\
        tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,inode64)\n\
        tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k,inode64)\n";
    CommandResult::ok(out)
}
