// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Display implementations for raw TBOR messages.
//!
//! - `Display` (`{}`) prints a human-readable summary with TOC entries.
//! - Alternate `Display` (`{:#}`) prints a hex dump of the raw bytes.

use core::fmt;

use crate::header::Header;
use crate::toc::TocEntry;
use crate::view::RequestView;
use crate::view::ResponseView;
use crate::view::View;

// ── Hex helpers ────────────────────────────────────────────────────────

/// Format a byte slice as a hex preview (up to 16 bytes, then `...`).
pub fn hex_preview(f: &mut fmt::Formatter<'_>, data: &[u8]) -> fmt::Result {
    let show = data.len().min(16);
    write!(
        f,
        "[{} byte{}] ",
        data.len(),
        if data.len() == 1 { "" } else { "s" }
    )?;
    for (i, b) in data[..show].iter().enumerate() {
        if i > 0 {
            write!(f, " ")?;
        }
        write!(f, "{:02x}", b)?;
    }
    if data.len() > 16 {
        write!(f, " ...")?;
    }
    Ok(())
}

/// Format a hex dump of raw bytes (16 bytes per line with ASCII sidebar).
pub fn hex_dump(f: &mut fmt::Formatter<'_>, data: &[u8]) -> fmt::Result {
    for (i, chunk) in data.chunks(16).enumerate() {
        write!(f, "{:04x}  ", i * 16)?;

        // Hex bytes in groups of 4.
        for (j, b) in chunk.iter().enumerate() {
            if j > 0 && j % 4 == 0 {
                write!(f, " ")?;
            }
            write!(f, "{:02x} ", b)?;
        }

        // Pad short last line.
        for j in 0..(16 - chunk.len()) {
            write!(f, "   ")?;
            if (chunk.len() + j) % 4 == 0 && j > 0 {
                write!(f, " ")?;
            }
        }

        // ASCII sidebar.
        write!(f, " ")?;
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '·'
            };
            write!(f, "{}", c)?;
        }
        writeln!(f)?;
    }
    Ok(())
}

// ── TOC entry formatting ───────────────────────────────────────────────

fn fmt_toc_entry(f: &mut fmt::Formatter<'_>, entry: TocEntry<'_>) -> fmt::Result {
    match entry {
        TocEntry::SessionId(v) => writeln!(f, "session_id  = 0x{:04X} ({})", v, v),
        TocEntry::KeyId(v) => writeln!(f, "key_id      = 0x{:04X} ({})", v, v),
        TocEntry::Uint8(v) => writeln!(f, "uint8       = 0x{:02X} ({})", v, v),
        TocEntry::Uint16(v) => writeln!(f, "uint16      = 0x{:04X} ({})", v, v),
        TocEntry::Uint32(v) => writeln!(f, "uint32      = 0x{:08X} ({})", v, v),
        TocEntry::Uint64(v) => writeln!(f, "uint64      = 0x{:016X} ({})", v, v),
        TocEntry::Buffer(b) => {
            write!(f, "buffer      ")?;
            hex_preview(f, b)?;
            writeln!(f)
        }
        TocEntry::SealedKey(b) => {
            write!(f, "sealed_key  ")?;
            hex_preview(f, b)?;
            writeln!(f)
        }
        TocEntry::None => writeln!(f, "none"),
        TocEntry::Padding(b) => writeln!(f, "padding     [{} bytes]", b.len()),
        TocEntry::Unknown {
            entry_type,
            raw_bits,
        } => writeln!(f, "unknown({})  raw=0x{:08X}", entry_type, raw_bits),
    }
}

/// Shared "list every TOC entry, one per line" body.
fn write_toc_entries<H: Header>(f: &mut fmt::Formatter<'_>, view: &View<'_, H>) -> fmt::Result {
    for i in 0..view.toc_count() {
        write!(f, "  TOC[{}]: ", i)?;
        fmt_toc_entry(f, view.toc_entry(i))?;
    }
    Ok(())
}

// ── Display for RequestView ────────────────────────────────────────────

impl fmt::Display for RequestView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            return hex_dump(f, self.as_bytes());
        }
        writeln!(
            f,
            "Request v{} opcode=0x{:02X} toc_count={} ({} bytes)",
            self.version(),
            self.opcode(),
            self.toc_count(),
            self.len(),
        )?;
        write_toc_entries(f, self)
    }
}

// ── Display for ResponseView ───────────────────────────────────────────

impl fmt::Display for ResponseView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            return hex_dump(f, self.as_bytes());
        }
        let flags_str = if self.fips_approved() {
            " flags=[FIPS]"
        } else {
            ""
        };
        writeln!(
            f,
            "Response v{} status=0x{:08X}{} toc_count={} ({} bytes)",
            self.version(),
            self.status(),
            flags_str,
            self.toc_count(),
            self.len(),
        )?;
        write_toc_entries(f, self)
    }
}
