// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Common helper functions

use std::collections::BTreeSet;
use std::path::PathBuf;

use xshell::cmd;
use xshell::Shell;

/// Return files tracked by git (excluding those from .gitignore), including
/// those which have not yet been staged / committed.
pub fn git_ls_files() -> anyhow::Result<Vec<PathBuf>> {
    let sh = Shell::new()?;

    macro_rules! as_set {
        ($cmd:literal) => {{
            let output = cmd!(sh, $cmd).output()?.stdout;
            let output = String::from_utf8_lossy(&output).to_string();
            output
                .split('\n')
                .map(PathBuf::from)
                .collect::<BTreeSet<_>>()
        }};
    }

    // "extra" corresponds to files not-yet committed to git
    let all = as_set!("git ls-files");
    let extra = as_set!("git ls-files --others --exclude-standard");
    let deleted = as_set!("git ls-files --deleted");

    let mut allow_list = all;
    allow_list.extend(extra);
    allow_list = allow_list.difference(&deleted).cloned().collect();

    // Vec is returned in sorted order because of BTreeSet iteration order
    Ok(allow_list.into_iter().collect())
}

/// Return target directory xtask builds to so that it doesn't overwrite itself
pub fn target_dir() -> anyhow::Result<PathBuf> {
    let sh = Shell::new()?;
    // use CARGO_TARGET_DIR if set, otherwise use local target directory
    let mut target_dir = PathBuf::from(sh.var("CARGO_TARGET_DIR").unwrap_or("target".to_string()));
    target_dir.push("xtask");
    Ok(target_dir)
}
