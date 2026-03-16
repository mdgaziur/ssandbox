use crate::SandboxConfig;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::unistd::{chdir, pivot_root};
use std::fs;
use std::path::Path;
use nix::sys::stat::{mknod, umask, Mode, SFlag};

pub fn setup_dev_mknod() -> anyhow::Result<()> {
    let dev_path = Path::new("/dev");
    fs::create_dir_all(dev_path)?;

    mount(
        Some("tmpfs"),
        dev_path,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("size=1m"),
    )?;

    let devices = [
        ("null",    1, 3),
        ("zero",    1, 5),
        ("full",    1, 7),
        ("random",  1, 8),
        ("urandom", 1, 9),
        ("tty",     5, 0),
        ("console", 5, 1),
    ];

    let old_umask = umask(Mode::empty());
    for (name, major, minor) in devices {
        let path = dev_path.join(name);
        let dev = nix::sys::stat::makedev(major, minor);
        mknod(
            &path,
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o666),
            dev,
        )?;
    }
    umask(old_umask);

    let symlinks = [
        ("/proc/self/fd", "fd"),
        ("/proc/self/fd/0", "stdin"),
        ("/proc/self/fd/1", "stdout"),
        ("/proc/self/fd/2", "stderr"),
    ];

    for (target, name) in symlinks {
        std::os::unix::fs::symlink(target, dev_path.join(name))?;
    }

    Ok(())
}

pub fn setup_fs(_config: &SandboxConfig, chroot_dir: &str) -> anyhow::Result<()> {
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;

    mount(
        Some(chroot_dir),
        chroot_dir,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )?;


    let put_old = Path::new(chroot_dir).join("old_root");
    fs::create_dir_all(&put_old)?;

    pivot_root(chroot_dir, &*put_old)?;
    chdir("/")?;

    umount2("/old_root", MntFlags::MNT_DETACH)?;
    fs::remove_dir("/old_root")?;

    fs::create_dir_all("/proc")?;
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )?;

    setup_dev_mknod()?;

    Ok(())
}