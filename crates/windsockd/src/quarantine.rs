//! `windsockd quarantine list` and `export`: read the quarantine of the local data directory.
//! No remote and no repository key: the local disk holds the records in clear.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use engine::{QuarantineReader, QuarantinedRecord};

use crate::config::Config;

fn quarantine(config: &Config) -> PathBuf {
    engine::quarantine_dir(config.data_dir.join("engine"))
}

/// One record as a tab-separated line: file, number, op, target, ack HLC, ack time, size, and
/// `ok` or `corrupt` for data that does not match its head.
fn line(record: &QuarantinedRecord) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        escape(&record.file),
        record.number,
        record.op,
        escape(&record.write.target),
        record.write.hlc,
        s3proto::time::iso8601(record.write.hlc),
        record.data.len(),
        match record.write.corrupt {
            true => "corrupt",
            false => "ok",
        }
    )
}

/// A client chooses the key: a control character, a tab, a newline or a backslash must not
/// start a new line or a terminal sequence.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c.is_control() && (c as u32) < 0x100 => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if c.is_control() => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Prints each record of the quarantine, and the intent files.
pub async fn list(config: &Config) -> Result<()> {
    let dir = quarantine(config);
    let mut reader = QuarantineReader::open(&dir)
        .await
        .with_context(|| format!("cannot read {}", dir.display()))?;
    let mut stdout = std::io::stdout().lock();
    let mut count = 0;
    while let Some(record) = reader.next().await? {
        writeln!(stdout, "{}", line(&record))?;
        count += 1;
    }
    for intent in intents(&dir)? {
        writeln!(stdout, "{}: interrupted flush, plan only", escape(&intent))?;
    }
    if count == 0 {
        writeln!(stdout, "the quarantine holds no record")?;
    }
    Ok(())
}

fn intents(dir: &Path) -> Result<Vec<String>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    for entry in entries {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name == "intent" || name.starts_with("intent.") {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Writes the body of each put to `<out>/<nnnn>.body` and every record to `<out>/index.tsv`.
/// `out` must not exist. Nothing in the quarantine changes.
pub async fn export(config: &Config, out: &Path) -> Result<()> {
    if std::fs::symlink_metadata(out).is_ok() {
        bail!(
            "{} exists: export writes to a new directory only",
            out.display()
        );
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(out)
        .with_context(|| format!("cannot create {}", out.display()))?;

    let dir = quarantine(config);
    let mut reader = QuarantineReader::open(&dir)
        .await
        .with_context(|| format!("cannot read {}", dir.display()))?;
    let mut index = String::from("n\tfile\tnumber\top\ttarget\tack_hlc\tack_time\tsize\n");
    let mut n = 0u64;
    while let Some(record) = reader.next().await? {
        n += 1;
        if record.op == "put" {
            let path = out.join(format!("{n:04}.body"));
            write_new(&path, &record.data).with_context(|| {
                format!(
                    "export stopped at record {n} ({}): cannot write {}",
                    escape(&record.write.target),
                    path.display()
                )
            })?;
        }
        index.push_str(&format!("{n:04}\t{}\n", line(&record)));
    }
    write_new(&out.join("index.tsv"), index.as_bytes())
        .context("export stopped: cannot write index.tsv")?;
    println!("exported {n} records to {}", out.display());
    Ok(())
}

/// A new file, readable by its owner only: the bodies are client data.
fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_keeps_a_key_on_one_line() {
        let key = "a\nb\tc\u{1b}[31md\\e\u{85}f";

        let escaped = escape(key);

        assert_eq!(escaped, "a\\x0ab\\x09c\\x1b[31md\\\\e\\x85f");
        assert!(!escaped.chars().any(char::is_control), "{escaped}");
    }
}
