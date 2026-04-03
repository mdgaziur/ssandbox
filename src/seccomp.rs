use std::collections::HashMap;
use extrasafe::{RuleSet, SeccompArgumentFilter, SeccompRule, SeccompilerComparator};
use extrasafe::syscalls::Sysno;
use nix::libc;

pub struct BasicSyscalls;

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
        ]
    }

    fn conditional_rules(&self) -> HashMap<Sysno, Vec<SeccompRule>> {
        let mut rules = HashMap::new();

        // 1. DUMPABLE RULE
        // Allow ONLY prctl(PR_SET_DUMPABLE) for setup, block all other prctl abuse
        let prctl_rule = SeccompRule::new(Sysno::prctl)
            .and_condition(SeccompArgumentFilter::new(
                0,
                SeccompilerComparator::Eq,
                libc::PR_SET_DUMPABLE as u64,
            ));
        rules.insert(Sysno::prctl, vec![prctl_rule]);

        // 2. READ-ONLY FILE ACCESS RULE
        // Allow the dynamic linker to open libraries, but strictly forbid writing/creating files
        // O_RDONLY in Linux evaluates to 0.
        // We also allow O_RDONLY | O_CLOEXEC (often used by libc).
        let openat_rule = SeccompRule::new(Sysno::openat)
            .and_condition(SeccompArgumentFilter::new(
                2,
                SeccompilerComparator::MaskedEq(libc::O_RDONLY as u64 | libc::O_RDWR as u64 | libc::O_CREAT as u64),
                0
            ));
        rules.insert(Sysno::openat, vec![openat_rule]);

        rules
    }

    fn name(&self) -> &'static str {
        "SandboxSyscalls"
    }
}
pub fn setup_seccomp() -> anyhow::Result<()> {
    extrasafe::SafetyContext::new()
        .enable(BasicSyscalls)?
        .apply_to_all_threads()?;

    Ok(())
}
