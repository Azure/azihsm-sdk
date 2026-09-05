// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Platform hook for commands the core does not implement.
//!
//! Both DDI dispatchers reject an opcode they do not recognise with
//! [`HsmError::UnsupportedCmd`](crate::HsmError::UnsupportedCmd). That is the right answer for a
//! production build, but it leaves no way for a platform to add commands
//! that exist purely to drive testing — crash injection, fault
//! injection, and similar.
//!
//! [`HsmCustomDispatch`] gives the platform one place to intercept an
//! otherwise-unsupported opcode.
//!
//! # When the hook is called, and what that requires of an implementer
//!
//! The two protocols reach the hook by different routes, and only one of
//! them can promise the opcode was unknown.
//!
//! **TBOR** consults the hook only when `is_known_opcode` has already
//! failed, so a TBOR hook genuinely cannot shadow a core command.
//!
//! **MBOR** consults the hook when core dispatch returns
//! [`UnsupportedCmd`](crate::HsmError::UnsupportedCmd). That is normally
//! the "no handler matched" answer, but it is not exclusively so: a
//! handler for a *known* opcode may also return it — `rsa_unwrap` does,
//! for an unsupported key type. So an MBOR hook can occasionally be
//! offered a request the core did recognise.
//!
//! **An implementer must therefore claim by opcode, and claim only
//! opcodes the core has no handler for.** Matching on the opcode and
//! returning `UnsupportedCmd` for everything else — as uno's
//! `test_dispatch` does — satisfies this. A hook that answered
//! unconditionally would shadow real commands.
//!
//! The alternative, a distinct "unknown opcode" signal out of MBOR
//! dispatch, was considered and rejected: it changes the core's
//! signature away from mainline's, and any second copy of the opcode
//! table needed to distinguish the two cases would rot.
//!
//! # Everything about such a command stays below the PAL
//!
//! MBOR and TBOR are host **API contracts**, and the layering runs
//! DDI handlers -> PAL trait -> platform adapters -> drivers. A
//! test-only command must not perforate that: nothing above the PAL may
//! know a `TestAction` exists, and no build above the PAL may be
//! feature-gated on it.
//!
//! So the hook is deliberately **opaque**. The core hands over the
//! untouched request buffer and gets back an encoded response; it never
//! learns the opcode, the request shape, or whether the platform even
//! claimed it. The opcode is not in any core table, the wire types are
//! not in any core crate, and the feature flag that turns the command on
//! lives in the uno PAL alone.
//!
//! The cost is that an implementer decodes the envelope and header for
//! itself, duplicating work the core already did for MBOR. That is the
//! price of the core staying oblivious, and it is what keeps the two
//! protocols' hooks identical in shape.
//!
//! # Contract
//!
//! The hook returns the encoded response as a slice borrowed from the
//! PAL's per-IO allocator, exactly as the core's own handlers do.
//!
//! Returning the slice — rather than filling a buffer the core
//! pre-allocates — is what keeps this cheap. The implementer allocates
//! *after* any `await`, so it can use
//! [`HsmAlloc::dma_alloc_var`](crate::HsmAlloc::dma_alloc_var), which
//! hands over the remaining watermark and returns the unused tail to the
//! pool. Pre-allocating a worst-case buffer for the hook to fill would
//! instead pin the per-IO high-water mark at that maximum, and that mark
//! drives the teardown scrub.
//!
//! Note an `async fn` may call `dma_alloc_var` freely; only `await`-ing
//! *inside* the closure is disallowed. Doing the asynchronous work first
//! and encoding afterwards is therefore the natural shape.
//!
//! # No default implementations
//!
//! Both methods are required. A platform that adds no test commands says
//! so explicitly by returning [`HsmError::UnsupportedCmd`](crate::HsmError::UnsupportedCmd) — see
//! `StdHsmPal`, which does exactly that for both protocols.
//!
//! Defaults would be shorter, but they make "this platform claims
//! nothing" the silent outcome of writing no code, which is the wrong
//! default for a hook whose entire purpose is to let a platform answer
//! commands the core refuses. Requiring the impl also means adding a
//! protocol to this trait breaks every platform until each one has
//! considered it.

use crate::DmaBuf;
use crate::HsmIo;
use crate::HsmResult;

/// Platform hook for opcodes the core does not implement.
///
/// MBOR and TBOR get separate entry points rather than one dispatcher
/// with a protocol discriminator: the two opcode spaces are disjoint,
/// the two core dispatchers apply different pre-gating before they reach
/// the fall-through, and a platform may want to extend one protocol
/// without touching the other.
pub trait HsmCustomDispatch {
    /// Handle an MBOR opcode the core does not implement.
    ///
    /// `req` is the whole request, exactly as it arrived. The core has
    /// decoded the envelope and header to learn the opcode, but hands
    /// over the original buffer rather than its decoder — passing a
    /// decoder would put DDI codec types in this crate, which sits below
    /// them, and would tell the core something about a command it must
    /// stay oblivious to.
    ///
    /// Taken by `&mut` because the MBOR decoder peels mutable
    /// sub-slices off the front, so byte fields can be borrowed in place
    /// rather than copied.
    ///
    /// # Parameters
    ///
    /// - `io` — the in-flight IO, for per-IO allocation.
    /// - `req` — the untouched request buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(resp)` — the encoded response, borrowed from the PAL's
    ///   per-IO allocator and valid until the IO completes.
    /// - `Err(HsmError::UnsupportedCmd)` — opcode not handled here
    ///   either; the core surfaces this to the host unchanged.
    async fn mbor_dispatch(&self, io: &impl HsmIo, req: &mut DmaBuf) -> HsmResult<&DmaBuf>;

    /// Handle a TBOR opcode the core does not implement.
    ///
    /// As with [`mbor_dispatch`](Self::mbor_dispatch), `req` is the
    /// whole request. TBOR rejects an unknown opcode before parsing
    /// anything, so nothing has been consumed in any case.
    ///
    /// The opcode is passed separately here only because TBOR's is a
    /// bare leading byte the core already has in hand; MBOR's sits
    /// inside the encoded header, and pulling it out for the hook would
    /// mean handing over a decoded DDI type.
    ///
    /// # Parameters
    ///
    /// - `io` — the in-flight IO, for per-IO allocation.
    /// - `opcode` — the opcode that was not recognised.
    /// - `req` — the untouched request buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(resp)` — the encoded response, borrowed from the PAL's
    ///   per-IO allocator and valid until the IO completes.
    /// - `Err(HsmError::UnsupportedCmd)` — opcode not handled here
    ///   either; the core surfaces this to the host unchanged.
    async fn tbor_dispatch(&self, io: &impl HsmIo, opcode: u8, req: &DmaBuf) -> HsmResult<&DmaBuf>;
}
