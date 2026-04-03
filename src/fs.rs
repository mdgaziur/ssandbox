use crate::{MountFlags, SandboxConfig};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sys::stat::{Mode, SFlag, mknod, umask};
use nix::unistd::{chdir, pivot_root};
use std::fs;
use std::path::Path;

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
        ("null", 1, 3),
        ("zero", 1, 5),
        ("full", 1, 7),
        ("random", 1, 8),
        ("urandom", 1, 9),
        ("tty", 5, 0),
        ("console", 5, 1),
    ];

    let old_umask = umask(Mode::empty());
    for (name, major, minor) in devices {
        let path = dev_path.join(name);
        let dev = nix::sys::stat::makedev(major, minor);
        mknod(&path, SFlag::S_IFCHR, Mode::from_bits_truncate(0o666), dev)?;
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

pub fn setup_fs(config: &SandboxConfig, chroot_dir: &str) -> anyhow::Result<()> {
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

    for mountpoint in &config.mountpoints {
        let target = Path::new(chroot_dir).canonicalize()?.join(
            mountpoint
                .target
                .strip_prefix("/")
                .unwrap_or(&mountpoint.target),
        );

        if !target.exists() {
            fs::create_dir_all(&target)?;
        }

        mount(
            Some(mountpoint.source.as_str()),
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )?;

        if matches!(mountpoint.flags, MountFlags::ReadOnly) {
            mount(
                None::<&str>,
                &target,
                None::<&str>,
                MsFlags::MS_BIND
                    | MsFlags::MS_REC
                    | MsFlags::MS_REMOUNT
                    | mountpoint.flags.to_linux_mount_flags(),
                None::<&str>,
            )?;
        }
    }

    let put_old = Path::new(chroot_dir).join("old_root");
    fs::create_dir_all(&put_old)?;

    pivot_root(chroot_dir, &*put_old)?;
    chdir("/")?;

    umount2("/old_root", MntFlags::MNT_DETACH)?;
    let _ = fs::remove_dir("/old_root");

    fs::create_dir_all("/tmp")?;
    mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(&*format!("size={},mode=1777", config.tmp_size)),
    )?;

    fs::create_dir_all("/proc")?;
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )?;

    setup_dev_mknod()?;

    if config.read_only_root {
        mount(
            Some("/"),
            "/",
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        )?;
    }

    Ok(())
}

pub fn extract_artifacts(config: &SandboxConfig, chroot_dir: &Path) -> anyhow::Result<()> {
    for extract_artifact in &config.extract_artifacts {
        let source = chroot_dir.join(
            extract_artifact
                .source
                .strip_prefix("/")
                .unwrap_or(&extract_artifact.source),
        );

        if source.exists() {
            let target = Path::new(&extract_artifact.target);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source, target)?;
        } else {
            anyhow::bail!(
                "Artifact source `{}` does not exist in chroot dir",
                extract_artifact.source
            );
        }
    }
    Ok(())
}
