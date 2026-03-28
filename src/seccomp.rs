use extrasafe::RuleSet;
use extrasafe::syscalls::Sysno;

pub struct BasicSyscalls;

impl RuleSet for BasicSyscalls {
    fn simple_rules(&self) -> Vec<Sysno> {
        vec![
            // Allow the sandbox itself to spawn the sandboxed process
            Sysno::execve,
            // GLibc initialization and TLS
            Sysno::arch_prctl,
            Sysno::set_tid_address,
            // Memory management syscalls
            Sysno::brk,
            Sysno::mmap,
            Sysno::mprotect,
            Sysno::munmap,
            // Allow the sandboxed process to exit
            Sysno::exit,
            Sysno::exit_group,
        ]
    }

    fn name(&self) -> &'static str {
        "BasicSyscalls"
    }
}

pub fn setup_seccomp() -> anyhow::Result<()> {
    extrasafe::SafetyContext::new()
        .enable(
            extrasafe::builtins::SystemIO::nothing()
                .allow_stdin()
                .allow_stdout()
                .allow_stderr(),
        )?
        .enable(BasicSyscalls)?
        .apply_to_all_threads()?;

    Ok(())
}
