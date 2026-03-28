use crate::cgroup::join_cgroup;
use crate::fs::setup_fs;
use crate::limit::setup_limits;
use crate::namespace::{setup_namespace0, setup_namespace1};
use crate::seccomp::setup_seccomp;
use crate::stdio::setup_stdio;
use crate::{SandboxChildError, SandboxChildErrorKind, SandboxConfig};
use fork::fork;
use nix::libc::{PR_SET_DUMPABLE, prctl};
use nix::sys::signal::kill;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{Gid, Pid, Uid, execve, getpid, setgroups, setresgid, setresuid};
use std::convert::Infallible;
use std::ffi::CString;
use std::fs::File;
use std::io::{Write, stderr, stdin, stdout};
use std::os::fd::{AsFd, BorrowedFd};

pub fn enter_child<Fd>(
    config: &SandboxConfig,
    mut child_err_writer: File,
    cgroup_name: &str,
    chroot_dir: &str,
    child_stdin: Option<Fd>,
    child_stdout: Option<Fd>,
    child_stderr: Option<Fd>,
) -> Infallible
where
    Fd: AsFd,
{
    if let Err(e) = setup_namespace0() {
        let serialized = bincode::serialize(&SandboxChildError {
            user_error: false,
            kind: SandboxChildErrorKind::SetupRuntimeFailed(e.to_string()),
        })
        .unwrap();
        let _ = child_err_writer.write_all(&serialized);

        std::process::exit(101);
    }

    match fork() {
        Ok(fork::Fork::Child) => enter_grandchild(
            config,
            child_err_writer,
            cgroup_name,
            chroot_dir,
            child_stdin,
            child_stdout,
            child_stderr,
        ),
        Ok(fork::Fork::Parent(child_pid)) => match waitpid(Pid::from_raw(child_pid), None) {
            Ok(status) => match status {
                WaitStatus::Exited(_, code) => std::process::exit(code),
                WaitStatus::Signaled(_, signal, _) => {
                    let _ = kill(getpid(), signal);

                    std::process::exit(128 + signal as i32)
                }
                _ => std::process::exit(1),
            },
            Err(e) => {
                let serialized = bincode::serialize(&SandboxChildError {
                    user_error: false,
                    kind: SandboxChildErrorKind::ForkFailed(e.to_string()),
                })
                .unwrap();
                let _ = child_err_writer.write_all(&serialized);

                std::process::exit(101);
            }
        },
        Err(e) => {
            let serialized = bincode::serialize(&SandboxChildError {
                user_error: false,
                kind: SandboxChildErrorKind::ForkFailed(e.to_string()),
            })
            .unwrap();
            let _ = child_err_writer.write_all(&serialized);

            std::process::exit(101);
        }
    }
}

pub fn enter_grandchild<Fd>(
    config: &SandboxConfig,
    mut child_err_writer: File,
    cgroup_name: &str,
    chroot_dir: &str,
    child_stdin: Option<Fd>,
    child_stdout: Option<Fd>,
    child_stderr: Option<Fd>,
) -> Infallible
where
    Fd: AsFd,
{
    if let Err(e) = setup_runtime(
        config,
        cgroup_name,
        chroot_dir,
        child_stdin,
        child_stdout,
        child_stderr,
        child_err_writer.as_fd(),
    ) {
        let serialized = bincode::serialize(&SandboxChildError {
            user_error: false,
            kind: SandboxChildErrorKind::SetupRuntimeFailed(e.to_string()),
        })
        .unwrap();
        let _ = child_err_writer.write_all(&serialized);

        std::process::exit(101);
    }

    execute(config).unwrap_or_else(|e| {
        let serialized = bincode::serialize(&e).unwrap();
        let _ = child_err_writer.write_all(&serialized);

        std::process::exit(101);
    })
}

fn execute(config: &SandboxConfig) -> Result<Infallible, SandboxChildError> {
    let executable = CString::new(&*config.executable_path).map_err(|_| SandboxChildError {
        user_error: true,
        kind: SandboxChildErrorKind::CStringEncodingFailed,
    })?;

    let executable_args = config
        .executable_args
        .iter()
        .map(|arg| CString::new(arg.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SandboxChildError {
            user_error: true,
            kind: SandboxChildErrorKind::CStringEncodingFailed,
        })?;

    let env = config
        .env
        .iter()
        .map(|(key, val)| CString::new(format!("{}={}", key, val)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SandboxChildError {
            user_error: true,
            kind: SandboxChildErrorKind::CStringEncodingFailed,
        })?;

    execve(&executable, &executable_args, &env).map_err(|e| SandboxChildError {
        user_error: true,
        kind: SandboxChildErrorKind::ExecFailed(e.to_string()),
    })
}

pub fn drop_privileges(child_err_writer: BorrowedFd) -> anyhow::Result<()> {
    let target_uid = Uid::from_raw(65534);
    let target_gid = Gid::from_raw(65534);

    let _ = nix::unistd::fchown(stdin().as_fd(), Some(target_uid), Some(target_gid));
    let _ = nix::unistd::fchown(stdout().as_fd(), Some(target_uid), Some(target_gid));
    let _ = nix::unistd::fchown(stderr().as_fd(), Some(target_uid), Some(target_gid));
    let _ = nix::unistd::fchown(child_err_writer, Some(target_uid), Some(target_gid));

    setgroups(&[])?;
    setresgid(target_gid, target_gid, target_gid)?;
    setresuid(target_uid, target_uid, target_uid)?;

    unsafe {
        prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    }

    Ok(())
}

pub fn setup_runtime<Fd>(
    config: &SandboxConfig,
    cgroup_name: &str,
    chroot_dir: &str,
    child_stdin: Option<Fd>,
    child_stdout: Option<Fd>,
    child_stderr: Option<Fd>,
    child_err_writer: BorrowedFd,
) -> anyhow::Result<()>
where
    Fd: AsFd,
{
    setup_stdio(child_stdin, child_stdout, child_stderr)?;
    join_cgroup(cgroup_name)?;
    setup_namespace1()?;
    setup_fs(config, chroot_dir)?;
    setup_limits(config)?;
    drop_privileges(child_err_writer)?;
    if !config.disable_strict_mode {
        setup_seccomp()?;
    }

    Ok(())
}
