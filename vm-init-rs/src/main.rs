/// Minimal init for bcachefs SRCU lock test VM.
///
/// Disk images are pre-populated on the host (prepare-vm-disks.sh).
/// This program mounts them, creates memory pressure while reconcile
/// moves data from SSD to HDD tier, and monitors for SRCU warnings.
use rustix::fs::{self, Mode, OFlags};
use rustix::mm::{self, MapFlags, ProtFlags};
use rustix::mount::{self, MountFlags, UnmountFlags};
use rustix::system;
use std::io::Write;
use std::time::Instant;

fn read_meminfo_field(field: &str) -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            let rest = rest.trim_start_matches(':').trim();
            let rest = rest.strip_suffix("kB").unwrap_or(rest).trim();
            return rest.parse().ok();
        }
    }
    None
}

fn eat_memory(mb: usize) -> usize {
    let mut consumed = 0usize;
    for _ in 0..mb {
        let size = 1024 * 1024;
        let result = unsafe {
            mm::mmap_anonymous(
                std::ptr::null_mut(),
                size,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::PRIVATE | MapFlags::POPULATE,
            )
        };
        let Ok(ptr) = result else { break };
        // Touch every page — don't mlock, so kernel can swap and we exercise reclaim
        unsafe {
            std::ptr::write_bytes(ptr.cast::<u8>(), 0x42, size);
        }
        consumed += 1;
        if consumed % 50 == 0 {
            println!("  ate {consumed} MB");
        }
    }
    consumed
}

/// Read /dev/kmsg non-blocking for SRCU warnings and allocation failures.
fn scan_kmsg() {
    let Ok(fd) = fs::open(
        "/dev/kmsg",
        OFlags::RDONLY | OFlags::NONBLOCK,
        Mode::empty(),
    ) else {
        return;
    };

    // Seek to end first (we only want new messages)
    let _ = rustix::fs::seek(&fd, rustix::fs::SeekFrom::End(0));

    let mut buf = [0u8; 8192];
    loop {
        match rustix::io::read(&fd, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let msg = String::from_utf8_lossy(&buf[..n]);
                for line in msg.lines() {
                    if line.contains("srcu")
                        || line.contains("page allocation failure")
                        || line.contains("warn_alloc")
                        || line.contains("oom")
                        || line.contains("reconcile")
                    {
                        println!("  KERNEL: {line}");
                    }
                }
            }
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("FATAL: {msg}");
    let _ = system::reboot(system::RebootCommand::PowerOff);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn main() {
    println!("=== bcachefs SRCU lock test ===");

    // Mount virtual filesystems
    let _ = mount::mount(c"none", c"/proc", c"proc", MountFlags::empty(), c"");
    let _ = mount::mount(c"none", c"/sys", c"sysfs", MountFlags::empty(), c"");
    let _ = mount::mount(c"none", c"/tmp", c"tmpfs", MountFlags::empty(), c"");
    let _ = mount::mount(c"devtmpfs", c"/dev", c"devtmpfs", MountFlags::empty(), c"");

    let mem_total = read_meminfo_field("MemTotal").unwrap_or(0);
    let mem_free = read_meminfo_field("MemFree").unwrap_or(0);
    println!("RAM: total={mem_total} kB free={mem_free} kB");

    // Wait for virtio devices
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Enable swap on /dev/vdc (unthrottled — matches real crash conditions)
    println!("=== Enabling swap ===");
    unsafe {
        if libc::swapon(c"/dev/vdc".as_ptr(), 0) != 0 {
            eprintln!("swapon failed: {}", std::io::Error::last_os_error());
        } else {
            println!("swap enabled on /dev/vdc");
        }
    }

    // Mount pre-populated bcachefs — reconcile starts automatically
    // (data is on SSD tier, background_target=hdd moves it to HDD)
    println!("=== Mounting bcachefs (pre-populated, reconcile will start) ===");
    let _ = std::fs::create_dir_all("/mnt/test");
    if let Err(e) = mount::mount(
        c"/dev/vda:/dev/vdb",
        c"/mnt/test",
        c"bcachefs",
        MountFlags::empty(),
        c"",
    ) {
        die(&format!("mount bcachefs: {e}"));
    }
    println!("bcachefs mounted");

    // Verify data exists (pre-populated by prepare-vm-disks.sh)
    match std::fs::read_dir("/mnt/test") {
        Ok(entries) => {
            let count = entries.filter_map(Result::ok).count();
            println!("files on disk: {count} (should be >0 if pre-populated)");
            if count == 0 {
                println!("WARNING: no files found — disk may not be pre-populated");
                println!("WARNING: reconcile won't have work to do");
            }
        }
        Err(e) => println!("WARNING: readdir failed: {e}"),
    }

    // Create memory pressure — eat MORE than physical RAM to force heavy swapping.
    // With 128M physical + 512M swap, eating 200M forces the kernel through
    // the reclaim path for every new page. If SRCU is held, reclaim deadlocks.
    let eat_target: usize = 200;
    let mem_total_mb = mem_total / 1024;
    println!("=== Starting memory pressure ({eat_target} MB on {mem_total_mb} MB physical) ===");

    let eater_pid = unsafe { libc::fork() };
    match eater_pid {
        0 => {
            // Child: eat memory and hold it
            let consumed = eat_memory(eat_target);
            println!("memory eater: holding {consumed} MB");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        -1 => die("fork failed"),
        _ => {} // Parent continues
    }

    // Heartbeat loop — if heartbeats stop, system is hung
    println!("=== Monitoring (120s) ===");
    let start = Instant::now();
    let mut stdout = std::io::stdout();
    let mut last_kmsg_check = 0u64;

    while start.elapsed().as_secs() < 120 {
        let elapsed = start.elapsed().as_secs();
        let mem_free = read_meminfo_field("MemFree").unwrap_or(0);
        let swap_free = read_meminfo_field("SwapFree").unwrap_or(0);
        println!("heartbeat t={elapsed}s free={mem_free}kB swap_free={swap_free}kB");
        let _ = stdout.flush();

        // Check kernel messages every 10s
        if elapsed >= last_kmsg_check + 10 {
            last_kmsg_check = elapsed;
            scan_kmsg();
        }

        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    println!("=== TEST PASSED: system remained responsive for 120s ===");

    // Cleanup
    unsafe {
        libc::kill(eater_pid, 9);
        libc::waitpid(eater_pid, std::ptr::null_mut(), 0);
    }
    let _ = mount::unmount(c"/mnt/test", UnmountFlags::empty());
    rustix::fs::sync();

    let _ = system::reboot(system::RebootCommand::PowerOff);
}
