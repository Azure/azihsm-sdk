// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the Apache-2.0 license

use std::fmt::Write;
use std::io;

use serde::Serialize;
use tinytemplate::TinyTemplate;

use crate::nextest_history_cache::write_history::TestRecord;

// The GitHub "HTML sanitizer" is incredibly sensitive to whitespace; do not attempt to break newlines.
static TEMPLATE: &str = r#"
<table>
  <tr><th>Commit</th><th>Author</th><th>Commit</th><th>Windows Total</th><th>Windows Skipped</th><th>Linux Total</th><th>Linux Skipped</th></tr>
{{ for record in records }}
  <tr>
    <td><a href="https://github.com/Azure/azihsm-sdk/commit/{ record.commit.id }">{ record.commit.id | trim_8 }</a></td>
    <td>{ record.commit.author | name_only }</td>
    <td>{ record.commit.title }</td>
    <td>{{ if record.tests.windows_total }}{ record.tests.windows_total }{{ else }}build error{{ endif }}</td><td>{{ if record.tests.windows_skipped }}{ record.tests.windows_skipped }{{ else }}build error{{ endif }}</td><td>{{ if record.tests.linux_total }}{ record.tests.linux_total }{{ else }}build error{{ endif }}</td><td>{{ if record.tests.linux_skipped }}{ record.tests.linux_skipped }{{ else }}build error{{ endif }}</td>
  </tr>
{{ endfor }}
</table>

"#;

pub(crate) fn format_records(records: &[TestRecord]) -> io::Result<String> {
    let mut tt = TinyTemplate::new();
    tt.add_formatter("name_only", |val, out| {
        if let Some(s) = val.as_str() {
            out.write_str(name_only(s))?;
        }
        Ok(())
    });
    tt.add_template("index", TEMPLATE).unwrap();
    tt.add_formatter("trim_8", |val, out| {
        if let Some(s) = val.as_str() {
            out.write_str(s.get(..8).unwrap_or(s))?;
        }
        Ok(())
    });

    Ok(tt
        .render(
            "index",
            &TemplateContext {
                records: records.to_vec(),
            },
        )
        .unwrap())
}

fn name_only(val: &str) -> &str {
    if let Some((name, _)) = val.split_once('<') {
        name.trim()
    } else {
        val
    }
}

#[derive(Serialize)]
struct TemplateContext {
    records: Vec<TestRecord>,
}
