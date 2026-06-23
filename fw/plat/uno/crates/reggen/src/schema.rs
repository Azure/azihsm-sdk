// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Intermediate representation for register blocks.
//!
//! This is the common schema that both firmware and peripheral code
//! generators consume.  It's produced by [`translate::from_ast`].

/// Software access type for a register field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldAccess {
    /// Read-write (default).
    RW,
    /// Read-only.
    RO,
    /// Write-only.
    WO,
    /// Write-1-to-clear.
    W1C,
    /// Write-1-to-set.
    W1S,
    /// Write clears all bits.
    WC,
}

/// A single bit-field within a register.
#[derive(Clone, Debug)]
pub struct Field {
    /// Field name (e.g., `EN`, `MATCH_FLAG`).
    pub name: String,
    /// Bit offset within the 32-bit register.
    pub offset: u32,
    /// Width in bits.
    pub width: u32,
    /// Software access type.
    pub access: FieldAccess,
    /// Reset value.
    pub reset: u64,
    /// Description.
    pub desc: String,
}

/// A 32-bit memory-mapped register (or register array).
#[derive(Clone, Debug)]
pub struct Register {
    /// Register name (e.g., `CR`, `SR`, `ISER`).
    pub name: String,
    /// Byte offset from the peripheral base address.
    pub offset: u32,
    /// Fields within this register.
    pub fields: Vec<Field>,
    /// Description.
    pub desc: String,
    /// Array count (`None` for scalar registers, `Some(n)` for arrays of `n` registers).
    /// Array elements are contiguous with a stride of 4 bytes.
    pub count: Option<u32>,
}

impl Register {
    /// Compute the combined access type of the register.
    ///
    /// Returns `RO` if all fields are `RO`, `WO` if all are `WO`,
    /// otherwise `RW`.
    pub fn combined_access(&self) -> FieldAccess {
        if self.fields.iter().all(|f| f.access == FieldAccess::RO) {
            FieldAccess::RO
        } else if self.fields.iter().all(|f| f.access == FieldAccess::WO) {
            FieldAccess::WO
        } else {
            FieldAccess::RW
        }
    }
}

/// A regfile instance — a group of registers forming a logical entry,
/// optionally arrayed with a stride.
#[derive(Clone, Debug)]
pub struct RegFile {
    /// Instance name (e.g., `ISQ`, `ICQ`).
    pub name: String,
    /// Type name for the generated struct (e.g., `isq_entry`).
    pub type_name: String,
    /// Byte offset from the peripheral base address.
    pub offset: u32,
    /// Byte stride between array entries (equals entry size after padding).
    pub stride: u32,
    /// Array count.
    pub count: u32,
    /// Child registers within each entry, in offset order.
    pub children: Vec<Register>,
    /// Description.
    pub desc: String,
}

impl RegFile {
    /// Compute the byte size of one entry (last child offset + 4).
    pub fn entry_size(&self) -> u32 {
        self.children
            .iter()
            .map(|r| r.offset + 4)
            .max()
            .unwrap_or(0)
    }
}

/// An item within a register block — either a scalar/array register,
/// a regfile (group of registers forming a logical entry), or a memory
/// region (opaque byte buffer).
#[derive(Clone, Debug)]
pub enum BlockItem {
    Reg(Register),
    RegFile(RegFile),
    Mem(MemRegion),
}

impl BlockItem {
    /// Byte offset of this item within the peripheral.
    pub fn offset(&self) -> u32 {
        match self {
            BlockItem::Reg(r) => r.offset,
            BlockItem::RegFile(rf) => rf.offset,
            BlockItem::Mem(m) => m.offset,
        }
    }

    /// Byte span of this item (offset past the last byte).
    pub fn end_offset(&self) -> u32 {
        match self {
            BlockItem::Reg(r) => r.offset + r.count.unwrap_or(1) * 4,
            BlockItem::RegFile(rf) => rf.offset + rf.count * rf.stride,
            BlockItem::Mem(m) => m.offset + m.count * m.stride,
        }
    }
}

/// An opaque memory region (SystemRDL `mem` component).
///
/// Generates base/offset/count/stride/size constants and a reserved
/// gap in the register struct. No individual register fields.
#[derive(Clone, Debug)]
pub struct MemRegion {
    /// Instance name (e.g., `IO_BUF`).
    pub name: String,
    /// Byte offset from the peripheral base address.
    pub offset: u32,
    /// Size of one entry in bytes.
    pub entry_size: u32,
    /// Number of entries.
    pub count: u32,
    /// Byte stride between entries (≥ entry_size).
    pub stride: u32,
    /// Description.
    pub desc: String,
}

/// A peripheral's register block.
#[derive(Clone, Debug)]
pub struct RegisterBlock {
    /// Peripheral name (e.g., `match_timer`, `trace_mailbox`).
    pub name: String,
    /// Base address.
    pub base_addr: u32,
    /// Items in offset order (registers and regfiles interleaved).
    pub items: Vec<BlockItem>,
    /// Description.
    pub desc: String,
}

impl RegisterBlock {
    /// Iterate over plain registers only (for backward compatibility).
    pub fn registers(&self) -> impl Iterator<Item = &Register> {
        self.items.iter().filter_map(|item| match item {
            BlockItem::Reg(r) => Some(r),
            _ => None,
        })
    }

    /// Iterate over regfile instances only.
    pub fn regfiles(&self) -> impl Iterator<Item = &RegFile> {
        self.items.iter().filter_map(|item| match item {
            BlockItem::RegFile(rf) => Some(rf),
            _ => None,
        })
    }

    /// Iterate over memory regions only.
    pub fn mem_regions(&self) -> impl Iterator<Item = &MemRegion> {
        self.items.iter().filter_map(|item| match item {
            BlockItem::Mem(m) => Some(m),
            _ => None,
        })
    }
}

/// Top-level SoC schema: a collection of peripheral register blocks.
#[derive(Clone, Debug)]
pub struct SocSchema {
    /// Schema name (e.g., the target identifier).
    pub name: String,
    /// Peripheral register blocks.
    pub blocks: Vec<RegisterBlock>,
}
