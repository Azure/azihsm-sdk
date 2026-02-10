// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::env::{self};
use std::fs;
use std::io;
use std::path::Path;

use serde::Deserialize;
use serde::Serialize;

use crate::nextest_history_cache::cache::Cache;
use crate::nextest_history_cache::cache::FsCache;
use crate::nextest_history_cache::cache_gha::GithubActionCache;
use crate::nextest_history_cache::git;
use crate::nextest_history_cache::html;
use crate::nextest_history_cache::util::other_err;

// Increment when non-backwards-compatible changes are made to the cache record
// format
const CACHE_FORMAT_VERSION: &str = "v2";

#[derive(Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
struct Tests {
    windows_total: i32,
    windows_skipped: i32,
    linux_total: i32,
    linux_skipped: i32,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TestRecord {
    commit: git::CommitInfo,
    tests: Tests,
}

pub fn write_history() -> io::Result<()> {
    let cache = GithubActionCache::new().map(box_cache).or_else(|e| {
        let fs_cache_path = "/tmp/azihsm-sdk-test-cache";
        println!(
            "Unable to create github action cache: {e}; using fs-cache instead at {fs_cache_path}"
        );
        FsCache::new(fs_cache_path.into()).map(box_cache)
    })?;

    let worktree = git::WorkTree::new(Path::new("/tmp/azihsm-sdk-test-history-wt"))?;
    let head_commit = worktree.head_commit_id()?;

    let is_pr = env::var("EVENT_NAME").is_ok_and(|name| name == "pull_request")
        && env::var("PR_BASE_COMMIT").is_ok();

    // require linear history for PRs; non-linear is OK for main branches
    /*if is_pr && !worktree.is_log_linear()? {
        println!("git history is not linear; attempting to squash PR");
        let (Ok(pull_request_title), Ok(base_ref)) =
            (env::var("PR_TITLE"), env::var("PR_BASE_COMMIT"))
        else {
            return Err(other_err("cannot attempt squash outside of a PR"));
        };
        let mut rebase_onto: String = base_ref;
        for merge_parents in worktree.merge_log()? {
            for parent in merge_parents {
                if worktree.is_ancestor(&parent, "remotes/origin/main")?
                    && !worktree.is_ancestor(&parent, &rebase_onto)?
                {
                    println!(
                        "Found more recent merge from main; will rebase onto {}",
                        parent
                    );
                    rebase_onto = parent;
                }
            }
        }
        println!("Resetting to {}", rebase_onto);
        worktree.reset_hard(&rebase_onto)?;
        println!("Set fs contents to {}", head_commit);
        worktree.set_fs_contents(&head_commit)?;
        println!("Committing squashed commit {pull_request_title:?}");
        worktree.commit(&pull_request_title)?;

        // we can't guarantee linear history even after squashing, so we can't check here
    }*/

    let git_commits = worktree.commit_log()?;

    env::set_current_dir(worktree.path)?;

    let mut records = vec![];

    // First record should always be pulled from current workflow's data to ensure it's up to date
    records.push(TestRecord {
        commit: git_commits[0].clone(),
        tests: get_tests(),
    });

    // Check cache for second record onward
    let mut cached_commit = None;
    for commit in git_commits.iter().skip(1) {
        match cache.get(&format_cache_key(&commit.id)) {
            Ok(Some(cached_records)) => {
                if let Ok(cached_records) =
                    serde_json::from_slice::<Vec<TestRecord>>(&cached_records)
                {
                    println!("Found cache entry for remaining commits at {}", commit.id);
                    records.extend(cached_records);
                    cached_commit = Some(commit.id.clone());
                    break;
                } else {
                    println!(
                        "Error parsing cache entry {:?}",
                        String::from_utf8_lossy(&cached_records)
                    );
                }
            }
            Ok(None) => {} // not found
            Err(e) => println!("Error reading from cache: {e}"),
        }
    }

    // Write all records back to cache, starting with most recent and stopping when we hit the cached commit (if any)
    for (i, record) in records.iter().enumerate() {
        if Some(&record.commit.id) == cached_commit.as_ref() {
            break;
        }
        if let Err(e) = cache.set(
            &format_cache_key(&record.commit.id),
            &serde_json::to_vec(&records[i..]).unwrap(),
        ) {
            println!(
                "Unable to write to cache for commit {}: {e}",
                record.commit.id
            );
        }
    }

    let html = html::format_records(&records)?;

    if let Ok(file) = env::var("GITHUB_STEP_SUMMARY") {
        fs::write(file, &html)?;
    } else {
        println!("{html}");
    }

    Ok(())
}

fn get_tests() -> Tests {
    let mut tests = Tests {
        windows_total: 0,
        windows_skipped: 0,
        linux_total: 0,
        linux_skipped: 0,
    };

    if let Ok(windows_total) = env::var("WINDOWS_TOTAL_TESTS") {
        tests.windows_total = windows_total.parse().unwrap_or(0);
    }

    if let Ok(windows_skipped) = env::var("WINDOWS_SKIPPED_TESTS") {
        tests.windows_skipped = windows_skipped.parse().unwrap_or(0);
    }

    if let Ok(linux_total) = env::var("LINUX_TOTAL_TESTS") {
        tests.linux_total = linux_total.parse().unwrap_or(0);
    }

    if let Ok(linux_skipped) = env::var("LINUX_SKIPPED_TESTS") {
        tests.linux_skipped = linux_skipped.parse().unwrap_or(0);
    }

    tests
}

fn box_cache(val: impl Cache + 'static) -> Box<dyn Cache> {
    Box::new(val)
}

fn format_cache_key(commit: &str) -> String {
    format!("{CACHE_FORMAT_VERSION}-{commit}")
}
