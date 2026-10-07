use serde_json::Value;
use unicode_width::UnicodeWidthChar;

pub fn print_json(value: &Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Print a `{ data, metadata }` list envelope: pretty JSON for `--json`,
/// otherwise `empty` when `data` has no rows, else the table `rows` builds.
pub fn print_list(
    res: &Value,
    json: bool,
    empty: &str,
    headers: &[&str],
    rows: impl FnOnce(&[Value]) -> Vec<Vec<String>>,
) -> anyhow::Result<()> {
    if json {
        return print_json(res);
    }
    let data = res
        .get("data")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    if data.is_empty() {
        println!("{empty}");
    } else {
        print!("{}", render_table(headers, &rows(data)));
    }
    Ok(())
}

/// The `data` object of a single-resource response such as `GET /v2/hosts/{id}`,
/// failing when it is missing or not an object. `kind` names the resource in
/// the error.
pub fn data_object<'a>(res: &'a Value, kind: &str) -> anyhow::Result<&'a Value> {
    res.get("data")
        .filter(|d| d.is_object())
        .ok_or_else(|| anyhow::anyhow!("unexpected response: missing {kind} data"))
}

/// A string field, empty when absent or not a string.
pub fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// An unsigned integer field as text, empty when absent.
pub fn count_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_u64)
        .map(|n| n.to_string())
        .unwrap_or_default()
}

/// The strings in an array field, joined with ", ".
pub fn joined_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `s` with control characters replaced by spaces, so API-supplied text
/// can't move the cursor or recolour the terminal.
pub fn sanitize_for_display(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Display width the way wcwidth-family terminals count it: one char at a
/// time, so a variation selector adds nothing and `☁️` (U+2601 U+FE0F) is one
/// column. `UnicodeWidthStr::width` applies Unicode emoji presentation instead
/// and calls that sequence two columns; Ghostty, Kitty and iTerm2 draw it that
/// way, while Alacritty (and Zed's terminal built on it), Terminal.app,
/// xterm.js and tmux draw one cell. No measure aligns on both sides; this one
/// matches the wcwidth side.
fn display_width(s: &str) -> usize {
    s.chars().filter_map(UnicodeWidthChar::width).sum()
}

/// Render rows as a left-aligned column table with a header row, padding each
/// column to its widest cell. Columns are separated by two spaces; the final
/// column is never padded (no trailing whitespace).
///
/// Widths are measured in terminal display columns (see [`display_width`]),
/// so wide glyphs (emoji, CJK) and combining marks align — a host named
/// `caleb-macbook-pro 💻` lines up with its plain-ASCII neighbours. Generic
/// over column count so every list command shares it.
pub fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.iter().map(|c| sanitize_for_display(c)).collect())
        .collect();
    let mut widths: Vec<usize> = headers.iter().map(|h| display_width(h)).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(display_width(cell));
            }
        }
    }

    let mut out = String::new();
    push_row(&mut out, headers, &widths);
    for row in rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        push_row(&mut out, &cells, &widths);
    }
    out
}

/// Render `label: value` lines with every value starting in the same column.
/// Rows whose value is empty are left out, so callers pass optional fields
/// unconditionally. Values are sanitized like table cells.
pub fn render_details(rows: &[(&str, String)]) -> String {
    let rows: Vec<(&str, String)> = rows
        .iter()
        .filter(|(_, v)| !v.trim().is_empty())
        .map(|(label, v)| (*label, sanitize_for_display(v)))
        .collect();
    let width = rows
        .iter()
        .map(|(label, _)| display_width(label))
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (label, value) in rows {
        let pad = width - display_width(label);
        out.push_str(&format!("{label}:{}  {value}\n", " ".repeat(pad)));
    }
    out
}

/// Append one padded row (newline-terminated) to `out`. The last cell is
/// emitted without trailing padding.
fn push_row(out: &mut String, cells: &[&str], widths: &[usize]) {
    let last = cells.len().saturating_sub(1);
    for (i, &cell) in cells.iter().enumerate() {
        out.push_str(cell);
        if i != last {
            let pad = widths
                .get(i)
                .copied()
                .unwrap_or(0)
                .saturating_sub(display_width(cell));
            out.push_str(&" ".repeat(pad));
            out.push_str("  ");
        }
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_details_aligns_values_and_skips_empty_rows() {
        let rows = [
            ("ID", "host-1".to_string()),
            ("Role", String::new()),
            ("IP addresses", "10.0.0.1".to_string()),
            ("Tags", "  ".to_string()),
        ];
        assert_eq!(
            render_details(&rows),
            "ID:            host-1\nIP addresses:  10.0.0.1\n"
        );
    }

    #[test]
    fn render_details_sanitizes_values() {
        let rows = [("Name", "evil\x1b[2Jname".to_string())];
        assert_eq!(render_details(&rows), "Name:  evil [2Jname\n");
    }

    #[test]
    fn data_object_rejects_missing_or_non_object_data() {
        let ok = serde_json::json!({"data": {"id": "host-1"}});
        assert_eq!(data_object(&ok, "host").unwrap()["id"], "host-1");
        for bad in [
            serde_json::json!({}),
            serde_json::json!({"data": []}),
            serde_json::json!({"data": null}),
        ] {
            let err = data_object(&bad, "host").unwrap_err().to_string();
            assert_eq!(err, "unexpected response: missing host data");
        }
    }

    #[test]
    fn render_table_aligns_columns_no_trailing_space() {
        let rows = vec![
            vec![
                "host-1".to_string(),
                "web".to_string(),
                "10.0.0.1".to_string(),
            ],
            vec![
                "h2".to_string(),
                "longer-name".to_string(),
                "10.0.0.2".to_string(),
            ],
        ];
        let out = render_table(&["ID", "NAME", "IP"], &rows);
        assert_eq!(
            out,
            "ID      NAME         IP\n\
             host-1  web          10.0.0.1\n\
             h2      longer-name  10.0.0.2\n"
        );
        // Last column is never padded.
        assert!(out.lines().all(|l| !l.ends_with(' ')));
    }

    #[test]
    fn render_table_aligns_wide_glyphs_by_display_width() {
        // 💻 is one char but two display columns; a naive char/byte count would
        // misalign the row after it. The final column must start at the same
        // *display* offset on every line.
        let rows = vec![
            vec!["a".to_string(), "laptop 💻".to_string(), "x".to_string()],
            vec!["b".to_string(), "pc".to_string(), "y".to_string()],
        ];
        let out = render_table(&["ID", "NAME", "C"], &rows);
        let last_col_offsets: Vec<usize> = out
            .lines()
            .map(|line| display_width(line) - 1) // every last cell here is 1 column wide
            .collect();
        assert!(
            last_col_offsets.windows(2).all(|w| w[0] == w[1]),
            "last column misaligned across rows: {last_col_offsets:?}"
        );
    }

    #[test]
    fn render_table_counts_vs16_emoji_as_one_column() {
        // ☁️ is U+2601 followed by VARIATION SELECTOR-16. wcwidth-family
        // terminals draw it in one cell, so the row must be padded as if the
        // name were seven columns wide, not eight.
        let rows = vec![
            vec![
                "a".to_string(),
                "Cloud \u{2601}\u{fe0f}".to_string(),
                "x".to_string(),
            ],
            vec!["b".to_string(), "Net".to_string(), "y".to_string()],
        ];
        let out = render_table(&["ID", "NAME", "C"], &rows);
        assert_eq!(
            out,
            "ID  NAME     C\n\
             a   Cloud \u{2601}\u{fe0f}  x\n\
             b   Net      y\n"
        );
    }

    mod sanitize {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn no_control_chars_survive(s in "\\PC*") {
                let out = sanitize_for_display(&s);
                assert!(
                    !out.chars().any(|c| c.is_control()),
                    "control character in output: {out:?}"
                );
            }

            #[test]
            fn non_control_chars_are_preserved(s in "[^\\p{Cc}]*") {
                assert_eq!(sanitize_for_display(&s), s);
            }

            #[test]
            fn length_is_preserved(s in "\\PC*") {
                assert_eq!(
                    sanitize_for_display(&s).chars().count(),
                    s.chars().count(),
                );
            }

            #[test]
            fn table_rows_stay_aligned(
                cells in prop::collection::vec("[\\x00-\\x1f\\x20-\\x7e]*", 1..5),
            ) {
                let rows = vec![cells];
                let headers: Vec<&str> = (0..rows[0].len()).map(|_| "H").collect();
                let out = render_table(&headers, &rows);
                assert!(
                    !out.lines().any(|l| l.contains('\n') || l.contains('\r')),
                    "embedded newline broke table row: {out:?}"
                );
            }
        }
    }
}
