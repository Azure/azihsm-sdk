/* Copyright (c) Microsoft Corporation. */
/* Licensed under the MIT License. */

MEMORY
{
    FLASH : ORIGIN = 0x00000000, LENGTH = 512K
    /* DTCM — CPU-only, holds stack and .bss.
       Upper region reserved (see rdl/soc/dtcm_map.rdl):
         0x2002_EC00  DTCM_IO_BUF[33]   (49.5 KB, 1.5 KB each)  — RECLAIMED
         0x2003_B400  DEV_ID_CERT_BLOB  (16 KB)
         0x2003_F400  CRASHDUMP_BASE    (1024 B)
         0x2003_F800  CORE_RUN_STATUS   (4 B)

       LENGTH runs to exactly 0x3B200, the end of DTCM_IO_BUF, because that
       region is dead: nothing in the firmware allocates from the NonDma heap
       it backs (zero call sites for HsmAlloc::alloc / alloc_zeroed outside
       the trait and PAL definitions), GDMA cannot reach the M7 TCM so no DMA
       targets it, and the slot scrub is driven by a dirty watermark that
       therefore never leaves zero. The 512 B reserved gap at 0x3B200 is
       deliberately left outside the region.

       Reclaiming it gives the stack the 49.5 KB it needs for ML-DSA, whose
       signing path peaks at ~153 KB of frame at ML-DSA-65. `heap_base_cap`
       reports zero capacity for that heap so any future NonDma allocation
       fails with NotEnoughSpace rather than handing out stack memory. */
    RAM   : ORIGIN = 0x20000000, LENGTH = 0x3B200
}

