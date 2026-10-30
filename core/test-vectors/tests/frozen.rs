use dotlock_test_vectors::{fingerprint, render, verify};
use std::{fs, process::Command};

#[test]
fn generated_bytes_match_frozen_fixture() {
    let frozen = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/v1/primitives.json")).unwrap();
    // Fixed independently of render(): changing generator + JSON must still fail.
    assert_eq!(
        fingerprint(&frozen),
        "fbcb08cc6caec1e32062fea0283d8a4bae895a5ccb6f77dbcd2975b49fb7ed5e"
    );
    assert!(render().unwrap() == frozen);
    verify(&frozen).unwrap();
    let mut altered = frozen;
    altered[0] ^= 1;
    assert!(verify(&altered).is_err());
}

#[test]
fn cli_never_overwrites_existing_or_mismatched_fixtures() {
    let dir = tempfile::tempdir().unwrap();
    let run = |mode| {
        Command::new(env!("CARGO_BIN_EXE_generate-vectors"))
            .arg(mode)
            .arg(dir.path())
            .output()
            .unwrap()
    };
    assert!(!run("--check").status.success());
    assert!(run("--init").status.success());
    let path = dir.path().join("primitives.json");
    let original = fs::read(&path).unwrap();
    assert!(run("--check").status.success());
    assert!(!run("--init").status.success());
    assert!(fs::read(&path).unwrap() == original);
    fs::write(&path, b"altered fixture").unwrap();
    assert!(!run("--check").status.success());
    assert!(fs::read(&path).unwrap() == b"altered fixture");
}
