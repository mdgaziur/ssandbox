#[cfg(target_arch = "x86_64")]
use std::collections::HashMap;
#[cfg(target_arch = "x86_64")]
use extrasafe::{RuleSet, SeccompArgumentFilter, SeccompRule, SeccompilerComparator};
#[cfg(target_arch = "x86_64")]
use extrasafe::syscalls::Sysno;
#[cfg(target_arch = "x86_64")]
use nix::libc;

#[cfg(target_arch = "x86_64")]
pub struct BasicSyscalls;

#[cfg(target_arch = "x86_64")]
impl RuleSet for BasicSyscalls {
    fn simple_rules(&self) -> Vec<Sysno> {
        vec![
            // Required for the Rust parent to finish setting up the jail
            Sysno::write,      // cgroup late-join
            Sysno::close,      // drop(cgroup_fd)

            // Execution and glibc boot
            Sysno::execve,
            Sysno::arch_prctl,
            Sysno::set_tid_address,
            Sysno::set_robust_list, // Often called by modern GLibc
            Sysno::rseq,            // Restartable sequences (Modern Linux/GLibc)

            // Required to load shared libraries like libc.so.6
            Sysno::read,
            Sysno::access,
            Sysno::fstat,
            Sysno::newfstatat,
            Sysno::pread64,
            Sysno::readlink,

            // Memory management
            Sysno::brk,
            Sysno::mmap,
            Sysno::mprotect,
            Sysno::munmap,

            // Teardown
            Sysno::exit,
            Sysno::exit_group,
            
            // Common utility syscalls for Go/Rust runtime boot
            Sysno::fcntl,
            Sysno::rt_sigprocmask,
            Sysno::rt_sigaction,
            Sysno::sigaltstack,
            Sysno::gettid,
            Sysno::getpid,
            Sysno::getrandom,
            Sysno::sched_yield,
            Sysno::clone,
            Sysno::clone3,
            Sysno::futex,
            Sysno::madvise,
            Sysno::rt_sigreturn,
            Sysno::sched_getaffinity,
            Sysno::clock_gettime,
            Sysno::nanosleep,
            Sysno::epoll_create1,
            Sysno::epoll_ctl,
            Sysno::epoll_wait,
            Sysno::epoll_pwait,
            Sysno::pipe2,
            Sysno::lseek,
            Sysno::writev,
            Sysno::readv,
            Sysno::ioctl,
            Sysno::getcwd,
            Sysno::mremap,
            Sysno::statfs,
            Sysno::fstatfs,
            Sysno::open,
            Sysno::openat,
            Sysno::prctl,
            Sysno::stat,
            Sysno::lstat,
            Sysno::prlimit64,
            Sysno::getrlimit,
            Sysno::tgkill,
            Sysno::tkill,
            Sysno::uname,
            Sysno::sysinfo,
            Sysno::readlinkat,
        ]
    }

    fn conditional_rules(&self) -> HashMap<Sysno, Vec<SeccompRule>> {
        HashMap::new()
    }

    fn name(&self) -> &'static str {
        "SandboxSyscalls"
    }
}

pub fn setup_seccomp() -> anyhow::Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        extrasafe::SafetyContext::new()
            .enable(BasicSyscalls)?
            .apply_to_all_threads()?;
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Warning is printed during Sandbox::new() in the parent process before redirection
    }

    Ok(())
}
