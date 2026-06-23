// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GDMA driver types.

/// A 64-bit DMA address split into high and low 32-bit halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GdmaAddr {
    /// Lower 32 bits of the address.
    pub lo: u32,
    /// Upper 32 bits of the address.
    pub hi: u32,
}

impl GdmaAddr {
    /// Zero address constant.
    pub const ZERO: Self = Self { lo: 0, hi: 0 };

    /// Creates a [`GdmaAddr`] from a 32-bit address (hi = 0).
    pub const fn from_u32(addr: u32) -> Self {
        Self { lo: addr, hi: 0 }
    }

    /// Creates a [`GdmaAddr`] from a 64-bit address.
    pub const fn from_u64(addr: u64) -> Self {
        Self {
            lo: addr as u32,
            hi: (addr >> 32) as u32,
        }
    }
}

/// DMA buffer descriptor — PRP pair or SGL pair.
///
/// Maps directly to SQ DW8–15 (source) or DW12–15 (destination).
/// The variant selects the FMT bit in SQ DW0 (0 = PRP, 1 = SGL).
///
/// # Hardware Constraints (Uno GDMA)
///
/// - **PRP**: Max 4 KiB per transfer via PRP0 only. Must not cross a
///   4 KiB page boundary. PRP1 is reserved for future PRP list support.
/// - **SGL**: Only inline Data Block descriptors, max 4 KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdmaBuf {
    /// Physical Region Page pair.
    ///
    /// `prp0`: first page address, `prp1`: second page or PRP list pointer.
    Prp { prp0: GdmaAddr, prp1: GdmaAddr },
    /// Scatter Gather List descriptor pair.
    ///
    /// `sgl0`: first SGL descriptor, `sgl1`: second SGL descriptor.
    Sgl { sgl0: GdmaAddr, sgl1: GdmaAddr },
}

impl GdmaBuf {
    /// Returns the submission-queue `FMT` bit for this DMA buffer descriptor.
    ///
    /// # Arguments
    ///
    /// * `self` - The descriptor variant to encode for a GDMA submission queue entry.
    ///
    /// # Returns
    ///
    /// `0` for [`GdmaDmaBuf::Prp`] descriptors and `1` for [`GdmaDmaBuf::Sgl`] descriptors.
    #[inline]
    pub const fn fmt_bit(&self) -> u32 {
        match self {
            Self::Prp { .. } => 0,
            Self::Sgl { .. } => 1,
        }
    }

    /// Returns the four 32-bit words written to the submission queue for this descriptor.
    ///
    /// # Arguments
    ///
    /// * `self` - The descriptor whose addresses should be expanded into queue dwords.
    ///
    /// # Returns
    ///
    /// A `(u32, u32, u32, u32)` tuple containing `(first_lo, first_hi, second_lo, second_hi)`.
    #[inline]
    pub const fn to_dwords(&self) -> (u32, u32, u32, u32) {
        match self {
            Self::Prp { prp0, prp1 } => (prp0.lo, prp0.hi, prp1.lo, prp1.hi),
            Self::Sgl { sgl0, sgl1 } => (sgl0.lo, sgl0.hi, sgl1.lo, sgl1.hi),
        }
    }
}

/// Memory interface selector for DMA source or destination.
///
/// Maps to `SRC_IFC_SLCT` / `DST_IFC_SLCT` (8-bit) in SQ DW1.
///
/// # Hardware Constraints (Uno GDMA)
///
/// - At least one side of the transfer must be `Device`.
/// - `Host { ctrl_id: 0 }` is invalid (IFC_SLCT=0 means device); the
///   driver rejects this with [`GdmaError::INVALID_HOST_IFC`](crate::GdmaError::INVALID_HOST_IFC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemInterface {
    /// Device-local memory (DTCM, SRAM). `IFC_SLCT = 0`.
    Device,
    /// Host memory on the given controller.
    Host {
        /// Controller identifier written to the IFC_SLCT field.
        ctrl_id: u8,
    },
}

impl MemInterface {
    /// Returns the `IFC_SLCT` field value for this memory interface.
    ///
    /// # Arguments
    ///
    /// * `self` - The source or destination memory interface to encode.
    ///
    /// # Returns
    ///
    /// An 8-bit selector where [`MemInterface::Device`] maps to `0` and [`MemInterface::Host`] maps to its controller ID.
    #[inline]
    pub const fn ifc_slct(self) -> u8 {
        match self {
            Self::Device => 0,
            Self::Host { ctrl_id } => ctrl_id,
        }
    }

    /// Reports whether this interface encodes the invalid host selector value.
    ///
    /// # Arguments
    ///
    /// * `self` - The memory interface to validate.
    ///
    /// # Returns
    ///
    /// `true` when the interface is `Host { ctrl_id: 0 }`; otherwise `false`.
    #[inline]
    pub const fn is_invalid_host(&self) -> bool {
        matches!(self, Self::Host { ctrl_id: 0 })
    }
}
