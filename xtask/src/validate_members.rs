// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to validate that all path dependencies in the workspace are also listed as workspace members

use std::fs;
use std::path::Path;

use clap::Parser;
use toml_edit::DocumentMut;
use toml_edit::Value;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to validate that all path dependencies in the workspace are also listed as workspace members
#[derive(Parser)]
#[clap(
    about = "Validate that all path dependencies in the workspace are also listed as workspace members"
)]
pub struct ValidateMembers {
    /// Attempt to fix any missing workspace members
    #[clap(long)]
    pub fix: bool,
}

impl Xtask for ValidateMembers {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running validate_members");

        // read workspace Cargo.toml and parse into toml_edit DocumentMut
        let data: Vec<u8> = fs::read("Cargo.toml")?;
        let data_str = std::str::from_utf8(&data)?;
        let mut doc = data_str.parse::<DocumentMut>()?;

        // get workspace members from doc
        let members = doc["workspace"]["members"].as_array().unwrap().clone();
        let mut member_paths: Vec<&str> = Vec::new();
        for value in members.iter() {
            member_paths.push(value.as_str().unwrap());
        }

        // get internal dependency paths from doc
        let mut dep_paths: Vec<&str> = Vec::new();
        let dep_table = doc["workspace"]["dependencies"].as_table().unwrap().clone();
        for (_dep_str, dep_val) in dep_table.iter() {
            if dep_val.is_inline_table() {
                if dep_val.as_inline_table().unwrap().contains_key("path") {
                    dep_paths.push(dep_val.as_inline_table().unwrap()["path"].as_str().unwrap());
                }
            }
        }

        // filter dep_paths to those not in member_paths
        let mut non_member_paths: Vec<&str> = Vec::new();
        for dep_path in &dep_paths {
            if !member_paths
                .iter()
                .any(|m| Path::new(dep_path) == Path::new(m))
            {
                non_member_paths.push(dep_path);
            }
        }

        if self.fix {
            // update workspace members to include any missing paths
            let mut updated = false;
            for non_member_path in &non_member_paths {
                log::trace!("Adding missing workspace member: {}", non_member_path);
                doc["workspace"]["members"]
                    .as_array_mut()
                    .unwrap()
                    .push(Value::from(*non_member_path));
                updated = true;
            }

            if updated {
                fs::write("Cargo.toml", doc.to_string())?;
            }
        } else if !non_member_paths.is_empty() {
            // Error
            Err(anyhow::anyhow!(
                "Workspace members missing path dependencies: {:?}",
                non_member_paths
            ))?
        }

        log::trace!("done validate_members");

        Ok(())
    }
}
