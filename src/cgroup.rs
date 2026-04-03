use crate::SandboxConfig;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::{fs, thread};
use std::path::Path;
use std::time::Duration;

#[derive(Debug)]
pub struct CGroupError {
    io_error: String,
    cgroup_path: String,
    kind: CGroupErrorKind,
}

impl CGroupError {
    pub fn new(io_error: String, cgroup_path: String, kind: CGroupErrorKind) -> Self {
        Self {
            io_error,
            cgroup_path,
            kind,
        }
    }
}

impl Display for CGroupError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CGroup(at `{}`) Error: {}, kind: {}",
            self.cgroup_path, self.io_error, self.kind
        )
    }
}

impl Error for CGroupError {}

#[derive(Debug)]
pub enum CGroupErrorKind {
    CreationFailed,
    LimitSettingFailed { name: String, value: String },
}

impl Display for CGroupErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CGroupErrorKind::CreationFailed => write!(f, "create cgroup"),
            CGroupErrorKind::LimitSettingFailed { name, value } => {
                write!(f, "set limit `{}` to `{}`", name, value)
            }
        }
    }
}

fn generate_cgroup_name() -> String {
    let cgroup_id = uuid::Uuid::new_v4().to_string();
    format!("ssandbox_container_{}", cgroup_id)
}

pub fn setup_cgroup(config: &SandboxConfig) -> anyhow::Result<String> {
    let cgroup_name = generate_cgroup_name();
    let cgroup_path = format!("/sys/fs/cgroup/{}", cgroup_name);

    std::fs::create_dir(&cgroup_path).map_err(|e| {
        CGroupError::new(
            e.to_string(),
            cgroup_path.clone(),
            CGroupErrorKind::CreationFailed,
        )
    })?;

    /******************* Hardcoded values *******************/

    // Set swap to 0 to ensure strict RAM enforcement
    // std::fs::write(format!("{}/memory.swap.max", &cgroup_path), "0").map_err(|e| {
    //     CGroupError::new(
    //         e.to_string(),
    //         cgroup_path.clone(),
    //         CGroupErrorKind::LimitSettingFailed {
    //             name: "swap".to_string(),
    //             value: "0".to_string(),
    //         },
    //     )
    // })?;

    // Set CPU quota to 100% to allow full CPU usage
    std::fs::write(
        format!("{}/pids.max", &cgroup_path),
        config.limits.max_nproc.to_string(),
    )
    .map_err(|e| {
        CGroupError::new(
            e.to_string(),
            cgroup_path.clone(),
            CGroupErrorKind::LimitSettingFailed {
                name: "pids.max".to_string(),
                value: config.limits.max_nproc.to_string(),
            },
        )
    })?;

    // Set CPU quota to 100% to allow full CPU usage
    std::fs::write(format!("{}/cpu.max", &cgroup_path), "100000 100000").map_err(|e| {
        CGroupError::new(
            e.to_string(),
            cgroup_path.clone(),
            CGroupErrorKind::LimitSettingFailed {
                name: "cpu.max".to_string(),
                value: "100000 100000".to_string(),
            },
        )
    })?;

    /******************* User defined values *******************/

    // Set memory limit
    std::fs::write(
        format!("{}/memory.max", &cgroup_path),
        config.limits.memory_limit.to_string(),
    )
    .map_err(|e| {
        CGroupError::new(
            e.to_string(),
            cgroup_path.clone(),
            CGroupErrorKind::LimitSettingFailed {
                name: "memory".to_string(),
                value: config.limits.memory_limit.to_string(),
            },
        )
    })?;

    // Pin the number of CPUs the application can use
    std::fs::write(
        format!("{}/cpuset.cpus", &cgroup_path),
        config.pinned_cpu_core.to_string(),
    )
    .map_err(|e| {
        CGroupError::new(
            e.to_string(),
            cgroup_path.clone(),
            CGroupErrorKind::LimitSettingFailed {
                name: "cpu".to_string(),
                value: config.pinned_cpu_core.to_string(),
            },
        )
    })?;

    Ok(cgroup_name)
}

pub fn cgroup_check_oom(cgroup_name: &str) -> anyhow::Result<bool> {
    let oom_control = fs::read_to_string(format!("/sys/fs/cgroup/{}/memory.events", cgroup_name))?;

    Ok(oom_control
        .lines()
        .find(|line| line.starts_with("oom_kill"))
        .and_then(|line| line.split_whitespace().nth(1))
        .map(|value| value.parse().unwrap_or(0) >= 1)
        .unwrap_or(false))
}

pub fn cgroup_kill(cgroup_name: &str) -> anyhow::Result<()> {
    fs::write(format!("/sys/fs/cgroup/{}/cgroup.kill", cgroup_name), "1")?;
    Ok(())
}

pub fn remove_cgroup(cgroup_name: &str) -> std::io::Result<()> {
    fs::remove_dir(format!("/sys/fs/cgroup/{}", cgroup_name))
}

pub fn get_cgroup_memory_peak(cgroup_name: &str) -> anyhow::Result<u64> {
    // Path to the peak memory usage file in Cgroup v2
    let path = Path::new("/sys/fs/cgroup")
        .join(cgroup_name)
        .join("memory.peak");

    let content = fs::read_to_string(path)?;
    let bytes = content.trim().parse::<u64>()?;
    Ok(bytes)
}

pub fn get_cgroup_cpu_stats(cgroup_name: &str) -> anyhow::Result<(u64, u64)> {
    let path = Path::new("/sys/fs/cgroup")
        .join(cgroup_name)
        .join("cpu.stat");

    let content = fs::read_to_string(path)?;
    let mut user_ms = 0;
    let mut system_ms = 0;

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        match parts[0] {
            "user_usec" => {
                // Convert microseconds to milliseconds
                user_ms = parts[1].parse::<u64>().unwrap_or(0) / 1000;
            }
            "system_usec" => {
                system_ms = parts[1].parse::<u64>().unwrap_or(0) / 1000;
            }
            _ => {}
        }
    }

    Ok((user_ms, system_ms))
}

pub struct CGroupGuard<'a> {
    cgroup_name: &'a str,
}

impl<'a> CGroupGuard<'a> {
    pub fn new(cgroup_name: &'a str) -> Self {
        Self { cgroup_name }
    }
}

impl<'a> Drop for CGroupGuard<'a> {
    fn drop(&mut self) {
        let mut retries = 10;
        let mut delay = Duration::from_millis(10);

        loop {
            match remove_cgroup(self.cgroup_name) {
                Ok(_) => return,
                Err(e) => {
                    // 16 is EBUSY (Device or resource busy)
                    if e.raw_os_error() == Some(16) && retries > 0 {
                        thread::sleep(delay);
                        retries -= 1;
                        delay += Duration::from_millis(10); // Gradually wait longer
                        continue;
                    }

                    // If it's a different error (like NotFound), or we ran out of retries, bail out
                    // Note: If it's NotFound, it might have already been deleted, which is technically an Ok state for cleanup.
                    if e.kind() == std::io::ErrorKind::NotFound {
                        return;
                    }

                    eprintln!("Failed to remove cgroup '{}': {}", self.cgroup_name, e);
                }
            }
        }
    }
}
