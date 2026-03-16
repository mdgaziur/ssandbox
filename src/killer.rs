use nix::sys::signal;
use nix::unistd::Pid;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, atomic};
use std::thread;
use std::time::Duration;

/// Ensures a child process with given PID is running for given wall clock time(in milliseconds)
pub struct TimeLimitKiller {
    is_cleared: Arc<AtomicBool>,
    is_tle: Arc<AtomicBool>,
}

impl TimeLimitKiller {
    pub fn new(limit_msecs: u64, child: Pid) -> Self {
        let is_cleared = Arc::new(AtomicBool::new(false));
        let is_cleared_clone = is_cleared.clone();
        let is_tle = Arc::new(AtomicBool::new(false));
        let is_tle_clone = is_tle.clone();

        thread::spawn(move || {
            thread::sleep(Duration::from_millis(limit_msecs));

            if is_cleared_clone.load(atomic::Ordering::SeqCst) {
                return;
            }

            let _ = signal::kill(child, signal::Signal::SIGKILL);
            is_tle_clone.store(true, atomic::Ordering::SeqCst);
        });

        Self { is_cleared, is_tle }
    }

    /// Returns if the killer has killed the child due to the given execution wall time limit being
    /// exceeded
    pub fn is_tle(&self) -> bool {
        self.is_tle.load(atomic::Ordering::SeqCst)
    }

    /// Cancel the killer timer. If the timer has already killed the child, it has no effect
    pub fn cancel(&self) {
        self.is_cleared.store(true, atomic::Ordering::SeqCst);
    }
}
