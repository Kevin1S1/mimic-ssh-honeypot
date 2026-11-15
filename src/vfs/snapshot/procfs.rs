use crate::persona::Persona;

pub fn cpuinfo(persona: &Persona) -> String {
    let cpu = &persona.cpu;
    let mut out = String::new();
    for core in 0..persona.cpu_cores {
        out.push_str(&format!(
            "processor\t: {core}\n\
             vendor_id\t: {vendor}\n\
             cpu family\t: {family}\n\
             model\t\t: {model}\n\
             model name\t: {name}\n\
             stepping\t: {stepping}\n\
             microcode\t: {microcode}\n\
             cpu MHz\t\t: {mhz}.000\n\
             cache size\t: {cache} KB\n\
             physical id\t: 0\n\
             siblings\t: {cores}\n\
             core id\t\t: {core}\n\
             cpu cores\t: {cores}\n\
             apicid\t\t: {core}\n\
             initial apicid\t: {core}\n\
             fpu\t\t: yes\n\
             fpu_exception\t: yes\n\
             cpuid level\t: 13\n\
             wp\t\t: yes\n\
             flags\t\t: {flags}\n\
             bugs\t\t: {bugs}\n\
             bogomips\t: {bogomips}\n\
             clflush size\t: 64\n\
             cache_alignment\t: 64\n\
             address sizes\t: 46 bits physical, 48 bits virtual\n\
             power management:\n\n",
            core = core,
            vendor = cpu.vendor,
            family = cpu.family,
            model = cpu.model,
            name = cpu.name,
            stepping = cpu.stepping,
            microcode = cpu.microcode,
            mhz = cpu.mhz,
            cache = cpu.cache_kb,
            cores = persona.cpu_cores,
            flags = cpu.flags,
            bugs = cpu.bugs,
            bogomips = persona.bogomips(),
        ));
    }
    out
}

pub fn meminfo(persona: &Persona) -> String {
    let mem = persona.memory();
    let (total, free, available) = (mem.total, mem.free, mem.available);
    let (buffers, cached, sreclaim, shmem) =
        (mem.buffers, mem.cached, mem.sreclaimable, mem.shared);
    let active = total * 145 / 1000;
    let inactive = total * 72 / 1000;
    let anon = total * 64 / 1000;
    let mapped = total * 36 / 1000;
    let slab = total * 28 / 1000;
    let sunreclaim = slab - sreclaim;
    format!(
        "MemTotal:        {total} kB\n\
         MemFree:         {free} kB\n\
         MemAvailable:    {available} kB\n\
         Buffers:           {buffers} kB\n\
         Cached:           {cached} kB\n\
         SwapCached:            0 kB\n\
         Active:           {active} kB\n\
         Inactive:         {inactive} kB\n\
         SwapTotal:             0 kB\n\
         SwapFree:              0 kB\n\
         Dirty:                88 kB\n\
         Writeback:             0 kB\n\
         AnonPages:        {anon} kB\n\
         Mapped:            {mapped} kB\n\
         Shmem:               {shmem} kB\n\
         Slab:              {slab} kB\n\
         SReclaimable:      {sreclaim} kB\n\
         SUnreclaim:        {sunreclaim} kB\n"
    )
}

pub(super) const VERSION: &str = "Linux version 6.1.0-21-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)\n";

pub(super) fn proc_uptime() -> Vec<u8> {
    let up = crate::clock::uptime_secs();
    format!("{up}.42 {:.2}\n", up as f64 * 0.9846).into_bytes()
}

pub(super) fn proc_loadavg() -> Vec<u8> {
    b"0.08 0.03 0.01 1/128 9241\n".to_vec()
}
