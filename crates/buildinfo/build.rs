//! Embeds the git commit, commit time and dirty flag of the source tree, the
//! way the Go toolchain embeds `vcs.revision`, `vcs.time` and `vcs.modified`.
//! When git or the repository is unavailable (for example a crates.io
//! tarball), nothing is embedded and the version prints on its own.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let Some(git_dir) = git(&manifest_dir, &["rev-parse", "--absolute-git-dir"]) else {
        return;
    };
    let Some(top) = git(&manifest_dir, &["rev-parse", "--show-toplevel"]) else {
        return;
    };
    watch_tree(Path::new(&top), Path::new(&git_dir));

    let Some(commit) = git(&manifest_dir, &["rev-parse", "HEAD"]) else {
        return; // no commits yet
    };
    println!("cargo:rustc-env=FWKNOP_GIT_COMMIT={commit}");

    let mut time = Command::new("git");
    time.current_dir(&manifest_dir).env("TZ", "UTC").args([
        "log",
        "-1",
        "--format=%cd",
        "--date=format-local:%Y-%m-%dT%H:%M:%SZ",
    ]);
    if let Some(t) = output(time) {
        println!("cargo:rustc-env=FWKNOP_GIT_TIME={t}");
    }

    // Like Go's vcs.modified: any change, including untracked files.
    let dirty = git(&manifest_dir, &["status", "--porcelain"]).is_some_and(|s| !s.is_empty());
    println!("cargo:rustc-env=FWKNOP_GIT_DIRTY={dirty}");
}

/// Re-run when HEAD moves, the index changes, or anything in the work tree
/// outside `target/` changes, so the dirty flag stays accurate without
/// rebuilding on every `cargo build`.
fn watch_tree(top: &Path, git_dir: &Path) {
    for name in ["HEAD", "index", "packed-refs", "refs"] {
        println!("cargo:rerun-if-changed={}", git_dir.join(name).display());
    }
    if let Ok(entries) = std::fs::read_dir(top) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name == "target" || name == ".git" {
                continue;
            }
            println!("cargo:rerun-if-changed={}", entry.path().display());
        }
    }
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir).args(args);
    output(cmd)
}

fn output(mut cmd: Command) -> Option<String> {
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}
