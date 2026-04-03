use clap::Parser;
use ssandbox::{ArtifactExtraction, MountFlags, Mountpoint, Sandbox, SandboxConfig};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
struct Cli {
    /// Path to the executable(relative to root dir) to run in the sandbox
    #[arg(short, long)]
    executable: String,

    /// Arguments to pass to the executable
    #[arg(last = true)]
    executable_args: Vec<String>,

    /// Memory limit in bytes
    #[arg(short, long)]
    memory_limit: u64,

    /// Max file write size
    #[arg(short = 'f', long)]
    max_file_size: u64,

    /// Time limit in ms. Both of the cpu time and the wall clock time will be checked against this
    #[arg(short, long)]
    time_limit: u64,

    /// Max processes the executable can create
    #[arg(short = 'p', long)]
    max_nproc: u64,

    /// The CPU core to pin the executable to
    #[arg(short = 'c', long)]
    pinned_cpu_core: u8,

    /// Path to the root directory that will be copied into the sandbox's root directory
    #[arg(short, long)]
    root_dir: String,

    /// Path to the input file to be copied into the sandbox
    #[arg(short = 'i', long)]
    stdin: Option<String>,

    /// Path to the file where the sandboxed executable's stdout will be written
    #[arg(short = 'o', long)]
    stdout: Option<String>,

    /// Path to the file where the sandboxed executable's stderr will be written
    #[arg(short = 'x', long)]
    stderr: Option<String>,

    /// Disable strict syscall filtering.
    /// This allows networking and various other syscalls. Although I'm not sure if these will still
    /// work properly.
    #[arg(long)]
    disable_strict_mode: bool,

    /// Env vars
    #[arg(long, value_parser = parse_key_val)]
    env: Vec<(String, String)>,

    /// Extract files from the sandbox after execution. The format is `sandbox_path=host_path`.
    /// For example, `--extract-artifact /app/output.txt=./output.txt` will copy the file `/app/output.txt`
    /// from the sandbox to `./output.txt` on the host after execution.
    /// The sandbox path is relative to the sandbox's root directory, and the host path is relative to the current working directory.
    #[arg(long, value_parser = parse_key_val)]
    extract_artifact: Vec<(String, String)>,

    /// Mount points. The format is `host_path=sandbox_path`. For example, `--mount /tmp/data=/app/data`
    /// will mount the host directory `/tmp/data` to `/app/data` in the sandbox.
    /// The sandbox path is relative to the sandbox's root directory, and the host path is an absolute path on the host.
    /// By default, mounts are read-write. You can make them read-only by adding `:ro` suffix to the mount definition, e.g. `--mount /tmp/data=/app/data:ro`.
    #[arg(long, value_parser = parse_key_val)]
    mount: Vec<(String, String)>,

    /// Whether to make the root filesystem read-only.
    /// This will not change the r/w permissions of mount points defined by `--mount`.
    #[arg(long)]
    read_only_root: bool,

    /// Temp directory size in container (with size prefix. eg. 16m)
    #[arg(long, default_value = "16m")]
    tmp_size: String,
}

fn parse_key_val(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("invalid KEY=VALUE: no `=` found in `{s}`"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let stdin = if let Some(stdin) = &cli.stdin {
        if let Ok(stdin_content) = std::fs::read_to_string(stdin) {
            Some(stdin_content)
        } else {
            eprintln!("Failed to read input file: {}", stdin);
            return ExitCode::FAILURE;
        }
    } else {
        None
    };

    let config = SandboxConfig {
        executable_path: cli.executable,
        executable_args: cli.executable_args.clone(),
        env: cli.env.clone(),
        limits: ssandbox::SandboxLimits {
            memory_limit: cli.memory_limit,
            max_file_size: cli.max_file_size,
            time_limit: cli.time_limit,
            max_nproc: cli.max_nproc,
        },
        pinned_cpu_core: cli.pinned_cpu_core,
        disable_strict_mode: cli.disable_strict_mode,
        stdin,
        redirect_stdout: cli.stdout.is_some(),
        redirect_stderr: cli.stderr.is_some(),
        extract_artifacts: cli
            .extract_artifact
            .iter()
            .map(|(source, target)| ArtifactExtraction {
                source: source.clone(),
                target: target.clone(),
            })
            .collect(),
        mountpoints: cli
            .mount
            .iter()
            .map(|(source, target)| Mountpoint {
                source: source.clone(),
                target: target
                    .clone()
                    .strip_suffix(":ro")
                    .unwrap_or(target)
                    .to_string(),
                flags: if target.ends_with(":ro") {
                    MountFlags::ReadOnly
                } else {
                    MountFlags::ReadWrite
                },
            })
            .collect(),
        read_only_root: cli.read_only_root,
        tmp_size: cli.tmp_size,
    };

    let mut sandbox = match Sandbox::new(config) {
        Ok(sandbox) => sandbox,
        Err(e) => {
            eprintln!("Failed to create sandbox: {:?}", e);
            return ExitCode::FAILURE;
        }
    };

    let root_dir_path = Path::new(&cli.root_dir);
    if !root_dir_path.exists() {
        eprintln!("Root directory does not exist: {}", root_dir_path.display());
        return ExitCode::FAILURE;
    }

    if !root_dir_path.is_dir() {
        eprintln!(
            "Root directory is not a directory: {}",
            root_dir_path.display()
        );
        return ExitCode::FAILURE;
    }

    sandbox.clone_root(PathBuf::from(root_dir_path)).unwrap();

    let sandbox_result;
    match sandbox.run() {
        Ok(result) => {
            sandbox_result = result;
            println!("{:#?}", sandbox_result);
        }
        Err(e) => {
            eprintln!("Sandbox execution failed: {:?}", e);
            return ExitCode::FAILURE;
        }
    }

    if let Some(ref stdout) = cli.stdout {
        if let Err(e) = std::fs::write(stdout, sandbox_result.stdout) {
            eprintln!("Failed to write stdout to file: {}", e);
        } else {
            println!("Stdout written to `{}`", stdout);
        }
    }

    if let Some(ref stderr) = cli.stderr {
        if let Err(e) = std::fs::write(stderr, sandbox_result.stderr) {
            eprintln!("Failed to write stderr to file: {}", e);
        } else {
            println!("Stderr written to `{}`", stderr);
        }
    }

    ExitCode::SUCCESS
}
