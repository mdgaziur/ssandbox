#![feature(debug_closure_helpers)]

mod cgroup;
mod fs;
mod inmemory_file;
mod killer;
mod limit;
mod namespace;
mod runtime;
mod seccomp;
mod stdio;
pub mod unit;

use crate::cgroup::{
    CGroupGuard, cgroup_check_oom, cgroup_kill, get_cgroup_cpu_stats, get_cgroup_memory_peak,
};
use crate::fs::extract_artifacts;
use crate::inmemory_file::new_inmemory_file;
use crate::killer::TimeLimitKiller;
use crate::runtime::enter_child;
use fork::{Fork, fork};
use fs_extra::dir::copy;
use nix::fcntl::{FcntlArg, FdFlag};
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::fs::{File, read_dir};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::Instant;
use tempdir::TempDir;

#[derive(Debug)]
pub struct Sandbox {
    config: SandboxConfig,
    chroot_dir: TempDir,
}

impl Sandbox {
    pub fn new(config: SandboxConfig) -> anyhow::Result<Self> {
        let tmp_dir = TempDir::new("ssandbox")?;
        std::fs::write(
            "/sys/fs/cgroup/cgroup.subtree_control",
            "+cpu +memory +cpuset",
        )?;

        Ok(Self {
            config,
            chroot_dir: tmp_dir,
        })
    }

    /// Makes the sandbox have the same directory structure as the given root directory
    /// by copying the files and directories in the given root directory into the sandbox's root directory.
    ///
    /// Note that multiple calls to this function will cause the directory structure created by the previous
    /// call to be cleared and replaced by the directory structure created by the current call.
    pub fn clone_root(&self, file_path: PathBuf) -> anyhow::Result<()> {
        for entry in read_dir(self.chroot_dir.path())? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                std::fs::remove_dir_all(path)?;
            } else {
                std::fs::remove_file(path)?;
            }
        }

        copy(
            file_path,
            self.chroot_dir.path(),
            &fs_extra::dir::CopyOptions::new().content_only(true),
        )?;

        Ok(())
    }

    pub fn run(&mut self) -> anyhow::Result<SandboxResult> {
        let start_time = Instant::now();

        let child_stdin = if let Some(ref stdin) = self.config.stdin {
            let f = new_inmemory_file("ssandbox_stdin")?;
            f.as_file().write_all(stdin.as_bytes())?;
            f.as_file().seek(SeekFrom::Start(0))?;

            Some(f)
        } else {
            None
        };

        let child_stdout = if self.config.redirect_stdout {
            Some(new_inmemory_file("ssandbox_stdout")?)
        } else {
            None
        };

        let child_stderr = if self.config.redirect_stderr {
            Some(new_inmemory_file("ssandbox_stderr")?)
        } else {
            None
        };

        let cgroup_name = cgroup::setup_cgroup(&self.config)?;
        let (err_pipe_reader_fd, err_pipe_writer_fd) = nix::unistd::pipe()?;
        nix::fcntl::fcntl(&err_pipe_writer_fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;

        match fork()? {
            Fork::Parent(child_pid) => {
                let _guard = CGroupGuard::new(&cgroup_name);

                let mut err_pipe_reader = File::from(err_pipe_reader_fd);
                drop(err_pipe_writer_fd);

                let killer =
                    TimeLimitKiller::new(self.config.limits.time_limit, Pid::from_raw(child_pid));

                let status = match waitpid(Pid::from_raw(child_pid), None) {
                    Ok(status) => status,
                    Err(e) => {
                        killer.cancel();
                        cgroup_kill(&cgroup_name)?;

                        return Ok(SandboxResult {
                            sandbox_error: Some(SandboxError::WaitpidFailed(e.to_string())),
                            ..Default::default()
                        });
                    }
                };

                killer.cancel();
                cgroup_kill(&cgroup_name)?;

                let mut sandbox_error = None;
                if let Ok(err) = bincode::deserialize_from(&mut err_pipe_reader) {
                    sandbox_error = Some(SandboxError::ChildError(err));
                }

                let elapsed_wall_time = start_time.elapsed().as_millis() as u64;

                let (user_cpu_time, system_cpu_time) =
                    get_cgroup_cpu_stats(&cgroup_name).unwrap_or((0, 0));
                let elapsed_cpu_time = user_cpu_time + system_cpu_time;
                let peak_memory_usage = get_cgroup_memory_peak(&cgroup_name)?;
                let time_limit_exceeded = elapsed_cpu_time > self.config.limits.time_limit
                    || killer.is_tle()
                    || matches!(status, WaitStatus::Signaled(_, Signal::SIGXCPU, _));
                let memory_limit_exceeded = cgroup_check_oom(&cgroup_name)?;

                let mut stdout = String::new();
                if let Some(ref child_stdout) = child_stdout {
                    child_stdout.as_file().seek(SeekFrom::Start(0))?;
                    child_stdout.as_file().read_to_string(&mut stdout)?;
                }

                let mut stderr = String::new();
                if let Some(ref child_stderr) = child_stderr {
                    child_stderr.as_file().seek(SeekFrom::Start(0))?;
                    child_stderr.as_file().read_to_string(&mut stderr)?;
                }

                let exit_status = match status {
                    WaitStatus::Exited(_, code) => code,
                    WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
                    _ => 0,
                };
                let signal = match status {
                    WaitStatus::Exited(_, _) => 0,
                    WaitStatus::Signaled(_, sig, _) => sig as i32,
                    _ => 0,
                };

                extract_artifacts(&self.config, self.chroot_dir.path())?;

                Ok(SandboxResult {
                    elapsed_cpu_time,
                    elapsed_wall_time,
                    peak_memory_usage,
                    time_limit_exceeded,
                    memory_limit_exceeded,
                    output_limit_exceeded: matches!(
                        status,
                        WaitStatus::Signaled(_, Signal::SIGXFSZ, _)
                    ),
                    exit_status_code: exit_status,
                    signal,
                    runtime_error: signal != 0 && sandbox_error.is_none(),
                    system_error: sandbox_error.is_some(),
                    stdout,
                    stderr,
                    sandbox_error,
                })
            }
            Fork::Child => {
                let err_pipe_writer = File::from(err_pipe_writer_fd);
                drop(err_pipe_reader_fd);

                #[allow(unreachable_code)]
                {
                    enter_child(
                        &self.config,
                        err_pipe_writer,
                        &cgroup_name,
                        self.chroot_dir.path().to_str().unwrap(),
                        child_stdin
                            .as_ref()
                            .map(|child_stdin| child_stdin.as_file()),
                        if let Some(ref child_stdout) = child_stdout {
                            Some(child_stdout.as_file())
                        } else {
                            None
                        },
                        if let Some(ref child_stderr) = child_stderr {
                            Some(child_stderr.as_file())
                        } else {
                            None
                        },
                    );

                    unreachable!();
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, thiserror::Error, Clone, Default)]
#[error("Sandbox error(Is user error? {user_error}): {kind}")]
pub struct SandboxChildError {
    pub user_error: bool,
    #[source]
    pub kind: SandboxChildErrorKind,
}

#[derive(Serialize, Deserialize, Debug, thiserror::Error, Clone, Default)]
pub enum SandboxChildErrorKind {
    #[error("Failed to setup runtime: {0}")]
    SetupRuntimeFailed(String),
    #[error("Failed to execve: {0}")]
    ExecFailed(String),
    #[error("Failed to convert string to C string for execve: string contains interior null byte")]
    CStringEncodingFailed,
    #[error("Failed to fork: {0}")]
    ForkFailed(String),
    #[error("Failed to drop privileges: {0}")]
    DropPrivilegesFailed(String),
    #[default]
    #[error("Unknown error")]
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub enum SandboxError {
    #[default]
    Unknown,
    WaitpidFailed(String),
    ChildError(SandboxChildError),
}

impl Display for SandboxError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::WaitpidFailed(err) => write!(f, "Waitpid failed: {}", err),
            SandboxError::ChildError(err) => write!(f, "Sandbox child error: {}", err),
            &SandboxError::Unknown => write!(f, "Unknown error"),
        }
    }
}

impl Error for SandboxError {}

#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    pub limits: SandboxLimits,
    pub executable_path: String,
    pub executable_args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub pinned_cpu_core: u8,
    pub stdin: Option<String>,
    pub disable_strict_mode: bool,
    pub redirect_stdout: bool,
    pub redirect_stderr: bool,
    pub extract_artifacts: Vec<ArtifactExtraction>,
    pub mountpoints: Vec<Mountpoint>,
}

#[derive(Debug, Clone, Default)]
pub struct ArtifactExtraction {
    pub source: String,
    pub target: String,
}

#[derive(Debug, Clone, Default)]
pub struct Mountpoint {
    pub source: String,
    pub target: String,
    pub flags: MountFlags,
}

#[derive(Debug, Clone, Default)]
pub enum MountFlags {
    #[default]
    ReadOnly,
    ReadWrite,
}

impl MountFlags {
    pub fn to_linux_mount_flags(&self) -> nix::mount::MsFlags {
        match self {
            MountFlags::ReadOnly => nix::mount::MsFlags::MS_RDONLY,
            MountFlags::ReadWrite => nix::mount::MsFlags::empty(),
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SandboxLimits {
    /// Time limit in ms. Both of the cpu time and the wall clock time will be checked against this
    pub time_limit: u64,

    /// Memory limit in bytes
    pub memory_limit: u64,

    /// Max file write size
    pub max_file_size: u64,

    /// Max processes
    pub max_nproc: u64,
}

#[derive(Clone, Default)]
pub struct SandboxResult {
    pub elapsed_wall_time: u64,
    pub elapsed_cpu_time: u64,
    pub time_limit_exceeded: bool,
    pub peak_memory_usage: u64,
    pub memory_limit_exceeded: bool,
    pub output_limit_exceeded: bool,
    pub runtime_error: bool,
    pub system_error: bool,
    pub exit_status_code: i32,
    pub signal: i32,
    pub stdout: String,
    pub stderr: String,
    pub sandbox_error: Option<SandboxError>,
}

impl Debug for SandboxResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxResult")
            .field(
                "elapsed_wall_time",
                &UnitDisplay(self.elapsed_wall_time, "ms"),
            )
            .field(
                "elapsed_cpu_time",
                &UnitDisplay(self.elapsed_cpu_time, "ms"),
            )
            .field("time_limit_exceeded", &self.time_limit_exceeded)
            .field(
                "peak_memory_usage",
                &UnitDisplay(self.peak_memory_usage, "bytes"),
            )
            .field("memory_limit_exceeded", &self.memory_limit_exceeded)
            .field("output_limit_exceeded", &self.output_limit_exceeded)
            .field("runtime_error", &self.runtime_error)
            .field("system_error", &self.system_error)
            .field("sandbox_error", &self.sandbox_error)
            .field("exit_status_code", &self.exit_status_code)
            .field("signal", &self.signal)
            .field_with("stdout", |f| f.write_str("<omitted>"))
            .field_with("stdout", |f| f.write_str("<omitted>"))
            .finish()
    }
}

pub struct UnitDisplay<T>(pub T, pub &'static str);

impl<T: Display> Debug for UnitDisplay<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.0, self.1)
    }
}
