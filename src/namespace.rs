use nix::sched::{CloneFlags, unshare};

pub fn setup_namespace0() -> anyhow::Result<()> {
    unshare(CloneFlags::CLONE_NEWPID)?;

    Ok(())
}

pub fn setup_namespace1() -> anyhow::Result<()> {
    unshare(
        CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWNET,
    )?;

    Ok(())
}
