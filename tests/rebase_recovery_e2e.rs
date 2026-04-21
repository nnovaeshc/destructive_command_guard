//! End-to-end tests for rebase-recovery mode (issue #104).
//!
//! Verifies that the hook pipeline:
//! - Still denies `git checkout -- .` / `git restore <paths>` by default.
//! - Allows the same commands when a rebase is in progress.
//! - Allows the same commands when a `dcg rebase-recover` permit was issued.
//! - Consumes the permit after a single successful allow.
//! - Does NOT unblock unrelated destructive commands (e.g. `git reset --hard`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn dcg_binary() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps
    path.pop(); // debug
    path.push("dcg");
    path
}

/// Run the dcg hook with `command` and `cwd`, returning stdout.
/// Empty stdout ⇒ command was allowed.
fn run_hook_in(cwd: &Path, command: &str) -> String {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });

    let mut child = Command::new(dcg_binary())
        .current_dir(cwd)
        // Keep tests hermetic: don't share the test user's real dcg state.
        .env("HOME", cwd)
        .env("XDG_CONFIG_HOME", cwd.join("xdg"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg");

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        serde_json::to_writer(stdin, &input).expect("failed to write json");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Spawn `dcg rebase-recover` with a specific `ttl` in the given cwd.
fn run_rebase_recover(cwd: &Path, ttl_secs: Option<u64>) -> std::process::Output {
    let mut cmd = Command::new(dcg_binary());
    cmd.current_dir(cwd)
        .env("HOME", cwd)
        .env("XDG_CONFIG_HOME", cwd.join("xdg"))
        .arg("rebase-recover");
    if let Some(t) = ttl_secs {
        cmd.arg("--ttl").arg(t.to_string());
    }
    cmd.output().expect("failed to run dcg rebase-recover")
}

struct TempRepo {
    root: PathBuf,
}

impl TempRepo {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "dcg-rebase-e2e-{}-{}-{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(root.join(".git")).unwrap();
        Self { root }
    }

    fn start_rebase_merge(&self) {
        fs::create_dir_all(self.root.join(".git").join("rebase-merge")).unwrap();
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn default_blocks_checkout_discard_outside_rebase() {
    let repo = TempRepo::new("default-checkout");
    let out = run_hook_in(&repo.root, "git checkout -- .");
    assert!(
        !out.trim().is_empty(),
        "expected block, got empty (allowed) output"
    );
    assert!(out.contains("deny"), "expected deny decision: {out}");
    assert!(
        out.contains("checkout-discard"),
        "expected checkout-discard rule: {out}"
    );
}

#[test]
fn default_blocks_restore_worktree_outside_rebase() {
    let repo = TempRepo::new("default-restore");
    let out = run_hook_in(&repo.root, "git restore src/foo.rs src/bar.rs");
    assert!(
        !out.trim().is_empty(),
        "expected block, got empty (allowed) output"
    );
    assert!(out.contains("deny"), "expected deny decision: {out}");
    assert!(
        out.contains("restore-worktree"),
        "expected restore-worktree rule: {out}"
    );
}

#[test]
fn allows_checkout_discard_during_rebase() {
    let repo = TempRepo::new("during-rebase-checkout");
    repo.start_rebase_merge();
    let out = run_hook_in(&repo.root, "git checkout -- .");
    assert!(
        out.trim().is_empty(),
        "expected allow (empty output), got: {out}"
    );
}

#[test]
fn allows_restore_worktree_during_rebase() {
    let repo = TempRepo::new("during-rebase-restore");
    repo.start_rebase_merge();
    let out = run_hook_in(&repo.root, "git restore src/foo.rs");
    assert!(
        out.trim().is_empty(),
        "expected allow (empty output), got: {out}"
    );
}

#[test]
fn rebase_does_not_unblock_reset_hard() {
    // Critical safety test: during rebase, unrelated destructive commands
    // must STILL be blocked. Only the narrow recovery patterns are allowed.
    let repo = TempRepo::new("rebase-reset-hard");
    repo.start_rebase_merge();
    let out = run_hook_in(&repo.root, "git reset --hard");
    assert!(
        out.contains("deny"),
        "git reset --hard must stay blocked even during rebase: {out}"
    );
    assert!(
        out.contains("reset-hard"),
        "expected reset-hard rule: {out}"
    );
}

#[test]
fn permit_allows_checkout_discard_then_expires_after_use() {
    let repo = TempRepo::new("permit-single-shot");

    // Without permit: blocked.
    let out = run_hook_in(&repo.root, "git checkout -- .");
    assert!(out.contains("deny"), "pre-permit must block: {out}");

    // Issue permit.
    let recover = run_rebase_recover(&repo.root, Some(120));
    assert!(
        recover.status.success(),
        "dcg rebase-recover failed: stdout={} stderr={}",
        String::from_utf8_lossy(&recover.stdout),
        String::from_utf8_lossy(&recover.stderr)
    );
    assert!(
        repo.root
            .join(".dcg")
            .join("rebase-recovery-permit")
            .exists()
    );

    // With permit: allowed.
    let out = run_hook_in(&repo.root, "git checkout -- .");
    assert!(
        out.trim().is_empty(),
        "permit should allow checkout-discard: {out}"
    );

    // Permit was single-shot — subsequent call must block again.
    let out = run_hook_in(&repo.root, "git checkout -- .");
    assert!(
        out.contains("deny"),
        "permit must be consumed after one allow: {out}"
    );
}

#[test]
fn expired_permit_does_not_unblock() {
    let repo = TempRepo::new("permit-expired");

    // Write an already-expired permit directly.
    let permit_path = repo.root.join(".dcg").join("rebase-recovery-permit");
    fs::create_dir_all(permit_path.parent().unwrap()).unwrap();
    let expired_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(10);
    fs::write(&permit_path, format!("{expired_at}\n")).unwrap();

    let out = run_hook_in(&repo.root, "git checkout -- .");
    assert!(
        out.contains("deny"),
        "expired permit must NOT unblock: {out}"
    );
}

#[test]
fn permit_does_not_unblock_reset_hard() {
    // Another safety test: the permit is scoped to the narrow recovery
    // patterns only. `git reset --hard` must remain blocked.
    let repo = TempRepo::new("permit-not-reset-hard");
    let recover = run_rebase_recover(&repo.root, Some(120));
    assert!(recover.status.success());

    let out = run_hook_in(&repo.root, "git reset --hard");
    assert!(
        out.contains("deny"),
        "permit must not unblock reset-hard: {out}"
    );
    // And the permit should still be there (wasn't consumed by reset).
    assert!(
        repo.root
            .join(".dcg")
            .join("rebase-recovery-permit")
            .exists(),
        "non-matching command must not consume the permit"
    );
}

#[test]
fn block_message_mentions_rebase_recover() {
    // When dcg blocks these recovery-eligible rules, the message should
    // point the agent at `dcg rebase-recover` so they know how to proceed.
    let repo = TempRepo::new("block-message");
    let out = run_hook_in(&repo.root, "git checkout -- .");
    assert!(
        out.contains("dcg rebase-recover"),
        "checkout-discard block message should mention `dcg rebase-recover`: {out}"
    );

    let out = run_hook_in(&repo.root, "git restore src/foo.rs");
    assert!(
        out.contains("dcg rebase-recover"),
        "restore-worktree block message should mention `dcg rebase-recover`: {out}"
    );
}
