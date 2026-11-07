//! Sets WINDSOCKD_VERSION: the package version, and `+<commit>` in a git checkout.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let package = std::env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION");
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets it"));
    let workspace = manifest.join("../..");
    println!("cargo:rerun-if-changed=build.rs");

    let version = match commit(&workspace) {
        Some(commit) => format!("{package}+{commit}"),
        None => package,
    };
    println!("cargo:rustc-env=WINDSOCKD_VERSION={version}");
}

/// The short commit of HEAD, only when the workspace root is the top of its git checkout.
fn commit(workspace: &Path) -> Option<String> {
    let top = git(workspace, &["rev-parse", "--show-toplevel"])?;
    if Path::new(&top).canonicalize().ok()? != workspace.canonicalize().ok()? {
        return None;
    }
    let git_dir = PathBuf::from(git(workspace, &["rev-parse", "--absolute-git-dir"])?);
    // A linked worktree keeps its HEAD apart from the refs that all worktrees share.
    let common = PathBuf::from(git(
        workspace,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?);
    // A commit moves the branch ref, a checkout moves HEAD, and a gc packs the refs.
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    println!(
        "cargo:rerun-if-changed={}",
        common.join("packed-refs").display()
    );
    if let Some(branch) = git(workspace, &["symbolic-ref", "-q", "HEAD"]) {
        println!("cargo:rerun-if-changed={}", common.join(branch).display());
    }
    git(workspace, &["rev-parse", "--short", "HEAD"])
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    Some(text.trim().to_string())
}
