// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io;

use serde::Serialize;
use tinytemplate::TinyTemplate;

use crate::nextest_history_cache::write_history::TestRecord;

// The GitHub "HTML sanitizer" is incredibly sensitive to whitespace; do not attempt to break newlines.
static TEMPLATE: &str = r#"
<table>
  <tr><th>Commit</th><th>Author</th><th>Title</th><th>Windows Total</th><th>Windows Skipped</th><th>Linux Total</th><th>Linux Skipped</th></tr>
{{ for record in records }}
  <tr>
    <td><a href="https://github.com/Azure/azihsm-sdk/commit/{ record.commit.id }">{ record.commit.id | trim_8 }</a></td>
    <td>{ record.commit.author | name_only }</td>
    <td>{ record.commit.title }</td>
    <td>{ record.tests.windows_total }</td><td>{ record.tests.windows_skipped }</td><td>{ record.tests.linux_total }</td><td>{ record.tests.linux_skipped }</td>
  </tr>
{{ endfor }}
</table>

"#;

pub(crate) fn format_records(records: &[TestRecord]) -> io::Result<String> {
    let mut tt = TinyTemplate::new();
    tt.add_formatter("name_only", |val, out| {
        if let Some(s) = val.as_str() {
            tinytemplate::escape(name_only(s), out);
        }
        Ok(())
    });
    tt.add_template("index", TEMPLATE).unwrap();
    tt.add_formatter("trim_8", |val, out| {
        if let Some(s) = val.as_str() {
            tinytemplate::escape(s.get(..8).unwrap_or(s), out);
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

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a TestRecord for testing
    fn create_test_record(id: &str, author: &str, title: &str) -> TestRecord {
        // We need to use serde to create Tests since it's private
        // Build JSON using proper serialization to avoid escaping issues
        let json_value = serde_json::json!({
            "commit": {
                "id": id,
                "author": author,
                "title": title
            },
            "tests": {
                "windows_total": 0,
                "windows_skipped": 0,
                "linux_total": 0,
                "linux_skipped": 0
            }
        });
        serde_json::from_value(json_value).unwrap()
    }

    #[test]
    fn test_html_escaping_in_title() {
        let records = vec![create_test_record(
            "abc123def456789",
            "John Doe <john@example.com>",
            "Fix bug with <script>alert('xss')</script> & other <tags>",
        )];

        let result = format_records(&records).unwrap();

        // Verify that dangerous HTML is escaped in title
        assert!(
            !result.contains("<script>"),
            "Script tags should be escaped"
        );
        assert!(
            result.contains("&lt;script&gt;"),
            "Should contain escaped script tags"
        );
        assert!(
            !result.contains("</script>"),
            "Closing script tags should be escaped"
        );
        assert!(
            result.contains("&lt;/script&gt;"),
            "Should contain escaped closing script tags"
        );

        // Verify other HTML tags are escaped
        assert!(!result.contains("<tags>"), "HTML tags should be escaped");
        assert!(
            result.contains("&lt;tags&gt;"),
            "Should contain escaped tags"
        );

        // Verify ampersands are escaped
        assert!(result.contains("&amp;"), "Ampersands should be escaped");
    }

    #[test]
    fn test_html_escaping_in_author() {
        let records = vec![create_test_record(
            "abc123def456789",
            "<script>alert('bad')</script> Name <evil@example.com>",
            "Normal title",
        )];

        let result = format_records(&records).unwrap();

        // The name_only function extracts text before first '<', then escapes it
        // So "<script>..." becomes "" (empty before first <)
        assert!(
            !result.contains("<script>"),
            "Script tags in author should be escaped"
        );
        // Since name_only extracts text before '<', and author starts with '<',
        // the result will be an empty string, so we just verify no unescaped tags exist
    }

    #[test]
    fn test_commit_id_escaping() {
        // Test that even commit IDs with special chars are escaped (though they shouldn't have them in practice)
        let records = vec![create_test_record(
            "abc<123>def&456",
            "Author <email@example.com>",
            "Title",
        )];

        let result = format_records(&records).unwrap();

        // The commit ID goes through trim_8 formatter which should escape
        assert!(
            result.contains("&lt;123&gt;") || result.contains("abc&lt;123"),
            "Commit ID special chars should be escaped"
        );
    }
}
