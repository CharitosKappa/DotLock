use dotlock_test_vectors::{render, verify, Result, FILE_NAME};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process::ExitCode,
};

fn run() -> Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let mode = args.first().and_then(|s| s.to_str()).unwrap_or("--check");
    if args.len() > 2 || !matches!(mode, "--check" | "--init") {
        return Err("unsupported arguments".into());
    }
    let directory = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("v1"));
    let path = directory.join(FILE_NAME);
    if mode == "--init" {
        let bytes = render()?;
        fs::create_dir_all(&directory)?;
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    } else {
        verify(&fs::read(path)?)?;
    }
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("Public primitive fixture check/initialization succeeded.");
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("Vector operation failed; existing fixtures are never overwritten. See the vector README.");
            ExitCode::FAILURE
        }
    }
}
