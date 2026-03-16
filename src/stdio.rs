use nix::unistd::{dup2_stderr, dup2_stdin, dup2_stdout};
use std::os::fd::AsFd;

pub fn setup_stdio<Fd>(child_stdin: Option<Fd>, child_stdout: Option<Fd>, child_stderr: Option<Fd>) -> anyhow::Result<()>
where
    Fd: AsFd,
{
    if let Some(child_stdin) = child_stdin {
        dup2_stdin(child_stdin.as_fd())?;
    }

    if let Some(child_stdout) = child_stdout {
        dup2_stdout(child_stdout.as_fd())?;
    }

    if let Some(child_stderr) = child_stderr {
        dup2_stderr(child_stderr.as_fd())?;
    }

    Ok(())
}
