use rlimit::Resource;

pub fn set_maximum_size_of_created_files(size: u64) -> std::io::Result<()> {
    Resource::FSIZE.set(size, size)
}

pub fn disable_core_file() -> std::io::Result<()> {
    Resource::CORE.set(0, 0)
}

pub fn setup_limits(config: &crate::SandboxConfig) -> std::io::Result<()> {
    set_maximum_size_of_created_files(config.limits.max_file_size)?;
    disable_core_file()?;

    Ok(())
}
