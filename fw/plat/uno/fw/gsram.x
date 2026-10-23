/* Copyright (c) Microsoft Corporation. */
/* Licensed under the MIT License. */

SECTIONS
{
    .gsram_text : ALIGN(16)
    {
        __gsram_text_start = .;
        *(.text.*self_test*)
        *(.rodata.*self_test*)
        . = ALIGN(16);
        __gsram_text_end = .;
    } > GSRAM_CODE
}
INSERT BEFORE .text;

ASSERT(SIZEOF(.gsram_text) > 0, "No self-test sections selected for GSRAM");
