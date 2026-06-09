// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key-attestation report template generator.
//!
//! Builds the CBOR-encoded payload of a [`KeyAttestationReport`] using
//! `minicbor` with unique sentinel byte patterns in every variable
//! position, scans the resulting bytes to discover field offsets, then
//! emits `fw/core/crypto/key-report/src/template.rs` containing two
//! const byte arrays (`PAYLOAD_HEAD` / `PAYLOAD_TAIL`) split around
//! the variable-width `flags` field, plus offset constants for the
//! patchable holes.
//!
//! Output is committed (Linux-only).  Re-run via:
//!
//! ```sh
//! cargo run -p azihsm_fw_core_crypto_key_report_gen
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("azihsm_fw_core_crypto_key_report_gen requires minicbor and only runs on Linux.");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::PathBuf;

    use minicbor::Encoder;

    // Field sizes (kept in sync with builder.rs constants).
    const PUBLIC_KEY_MAX_SIZE: usize = 525;
    const PUBLIC_KEY_COORD_LEN: usize = 48;
    const APP_UUID_LEN: usize = 16;
    const REPORT_DATA_LEN: usize = 128;
    const VM_LAUNCH_ID_LEN: usize = 16;
    const PUBLIC_KEY_INNER_SIZE: u16 = 107;

    // Sentinels: a distinct byte per field, repeated through the
    // field length.  Choices avoid collision with structural CBOR
    // bytes that surround the holes.
    const SENTINEL_PK_X: u8 = 0xA1;
    const SENTINEL_PK_Y: u8 = 0xA2;
    const SENTINEL_APP_UUID: u8 = 0xA3;
    const SENTINEL_REPORT_DATA: u8 = 0xA4;
    const SENTINEL_VM_LAUNCH_ID: u8 = 0xA5;

    /// Placeholder byte written into the sanitized templates.
    const PLACEHOLDER_BYTE: u8 = 0x5F;

    pub fn run() {
        let payload = build_payload();
        // flags = 0 encodes as a single 0x00 byte. The HEAD ends
        // immediately after the `0x03` key marker; TAIL begins at the
        // `0x04` (app_uuid) key marker. Find their indices via the
        // unique `[0x03, 0x00, 0x04]` triplet.
        let triplet = [0x03_u8, 0x00, 0x04];
        let triplet_pos = find_unique(&payload, &triplet, "key3/flags/key4 triplet");
        let head_len = triplet_pos + 1; // up to and including 0x03
        let flags_value_offset = head_len;
        let tail_start = triplet_pos + 2; // skip flags=0 placeholder byte

        // Hole offsets, recorded against the encoded payload.
        let pk_x_payload = find_unique_byte_run(
            &payload,
            SENTINEL_PK_X,
            PUBLIC_KEY_COORD_LEN,
            "pk_x sentinel",
        );
        let pk_y_payload = find_unique_byte_run(
            &payload,
            SENTINEL_PK_Y,
            PUBLIC_KEY_COORD_LEN,
            "pk_y sentinel",
        );
        let app_uuid_payload = find_unique_byte_run(
            &payload,
            SENTINEL_APP_UUID,
            APP_UUID_LEN,
            "app_uuid sentinel",
        );
        let report_data_payload = find_unique_byte_run(
            &payload,
            SENTINEL_REPORT_DATA,
            REPORT_DATA_LEN,
            "report_data sentinel",
        );
        let vm_launch_id_payload = find_unique_byte_run(
            &payload,
            SENTINEL_VM_LAUNCH_ID,
            VM_LAUNCH_ID_LEN,
            "vm_launch_id sentinel",
        );

        // Sanity: pk_x / pk_y in HEAD; app_uuid / report_data /
        // vm_launch_id in TAIL.
        assert!(pk_x_payload + PUBLIC_KEY_COORD_LEN <= head_len);
        assert!(pk_y_payload + PUBLIC_KEY_COORD_LEN <= head_len);
        assert!(app_uuid_payload >= tail_start);
        assert!(report_data_payload >= tail_start);
        assert!(vm_launch_id_payload >= tail_start);

        // Sanitize: replace each sentinel run with PLACEHOLDER_BYTE.
        let mut sanitized = payload.clone();
        for off in [
            pk_x_payload,
            pk_y_payload,
            app_uuid_payload,
            report_data_payload,
            vm_launch_id_payload,
        ] {
            let len = match off {
                o if o == pk_x_payload || o == pk_y_payload => PUBLIC_KEY_COORD_LEN,
                o if o == app_uuid_payload => APP_UUID_LEN,
                o if o == report_data_payload => REPORT_DATA_LEN,
                o if o == vm_launch_id_payload => VM_LAUNCH_ID_LEN,
                _ => unreachable!(),
            };
            for i in 0..len {
                sanitized[off + i] = PLACEHOLDER_BYTE;
            }
        }

        let head = &sanitized[..head_len];
        let tail = &sanitized[tail_start..];

        // Convert payload-relative hole offsets into HEAD/TAIL-relative.
        let pk_x_head = pk_x_payload;
        let pk_y_head = pk_y_payload;
        let app_uuid_tail = app_uuid_payload - tail_start;
        let report_data_tail = report_data_payload - tail_start;
        let vm_launch_id_tail = vm_launch_id_payload - tail_start;

        // Independent cross-check: re-encode with flags = u32::MAX and
        // confirm the HEAD prefix is identical and TAIL appears at
        // the expected (shifted) position.
        let payload_max_flags = build_payload_with_flags(u32::MAX);
        assert_eq!(
            &payload_max_flags[..head_len],
            head_with_sentinels(&payload, head_len),
            "HEAD must be invariant in flags"
        );
        let max_flags_tail_start = head_len + 5;
        assert_eq!(
            &payload_max_flags[max_flags_tail_start..],
            &payload[tail_start..],
            "TAIL must be invariant in flags (only its position shifts)"
        );

        let src = emit_template_module(
            head,
            tail,
            head_len,
            tail.len(),
            pk_x_head,
            pk_y_head,
            app_uuid_tail,
            report_data_tail,
            vm_launch_id_tail,
            flags_value_offset,
            PUBLIC_KEY_INNER_SIZE,
        );

        let out_path = output_path();
        fs::create_dir_all(out_path.parent().unwrap()).expect("create src dir");
        fs::write(&out_path, src).expect("write template.rs");
        println!("Wrote {}", out_path.display());
        println!(
            "  payload bytes: {}, HEAD: {}, TAIL: {}",
            payload.len(),
            head_len,
            tail.len()
        );
    }

    fn head_with_sentinels(payload: &[u8], head_len: usize) -> &[u8] {
        &payload[..head_len]
    }

    fn build_payload() -> Vec<u8> {
        build_payload_with_flags(0)
    }

    fn build_payload_with_flags(flags: u32) -> Vec<u8> {
        // Outer payload = map(7) keyed 0..6.
        let mut public_key = vec![0u8; PUBLIC_KEY_MAX_SIZE];
        let inner = build_inner_cose_key();
        public_key[..inner.len()].copy_from_slice(&inner);

        let app_uuid = vec![SENTINEL_APP_UUID; APP_UUID_LEN];
        let report_data = vec![SENTINEL_REPORT_DATA; REPORT_DATA_LEN];
        let vm_launch_id = vec![SENTINEL_VM_LAUNCH_ID; VM_LAUNCH_ID_LEN];

        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.map(7)
            .unwrap()
            .u8(0)
            .unwrap()
            .u16(1)
            .unwrap() // version
            .u8(1)
            .unwrap()
            .bytes(&public_key)
            .unwrap() // public_key
            .u8(2)
            .unwrap()
            .u16(PUBLIC_KEY_INNER_SIZE)
            .unwrap() // public_key_size
            .u8(3)
            .unwrap()
            .u32(flags)
            .unwrap() // flags
            .u8(4)
            .unwrap()
            .bytes(&app_uuid)
            .unwrap() // app_uuid
            .u8(5)
            .unwrap()
            .bytes(&report_data)
            .unwrap() // report_data
            .u8(6)
            .unwrap()
            .bytes(&vm_launch_id)
            .unwrap(); // vm_launch_id
        buf
    }

    fn build_inner_cose_key() -> Vec<u8> {
        let x = vec![SENTINEL_PK_X; PUBLIC_KEY_COORD_LEN];
        let y = vec![SENTINEL_PK_Y; PUBLIC_KEY_COORD_LEN];
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        // map(4): KTY=EC2, CRV=P-384(2), X, Y
        enc.map(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap() // KTY = 1, EC2 = 2
            .i8(-1)
            .unwrap()
            .i8(2)
            .unwrap() // CRV = -1, P-384 = 2
            .i8(-2)
            .unwrap()
            .bytes(&x)
            .unwrap() // X = -2
            .i8(-3)
            .unwrap()
            .bytes(&y)
            .unwrap(); // Y = -3
        buf
    }

    fn find_unique(hay: &[u8], needle: &[u8], desc: &str) -> usize {
        let mut found = None;
        let mut i = 0;
        while i + needle.len() <= hay.len() {
            if &hay[i..i + needle.len()] == needle {
                assert!(found.is_none(), "{desc}: multiple matches");
                found = Some(i);
            }
            i += 1;
        }
        found.unwrap_or_else(|| panic!("{desc}: not found"))
    }

    fn find_unique_byte_run(hay: &[u8], byte: u8, len: usize, desc: &str) -> usize {
        let needle = vec![byte; len];
        find_unique(hay, &needle, desc)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_template_module(
        head: &[u8],
        tail: &[u8],
        head_len: usize,
        tail_len: usize,
        pk_x_head: usize,
        pk_y_head: usize,
        app_uuid_tail: usize,
        report_data_tail: usize,
        vm_launch_id_tail: usize,
        flags_value_offset: usize,
        public_key_inner_size: u16,
    ) -> String {
        let mut s = String::new();
        s.push_str("// Copyright (c) Microsoft Corporation.\n");
        s.push_str("// Licensed under the MIT License.\n\n");
        s.push_str(
            "// AUTO-GENERATED by azihsm_fw_core_crypto_key_report_gen. Do not edit manually.\n\n",
        );
        s.push_str("//! Pre-baked CBOR templates for the key-attestation report payload.\n");
        s.push_str("//!\n");
        s.push_str("//! The payload is split around the variable-width `flags: u32` field.\n");
        s.push_str("//! At runtime the builder emits:\n");
        s.push_str("//!\n");
        s.push_str("//!     PAYLOAD_HEAD ++ canonical_u32(flags) ++ PAYLOAD_TAIL\n");
        s.push_str("//!\n");
        s.push_str("//! Holes inside HEAD/TAIL are patched in place with caller inputs.\n\n");

        emit_const_array(&mut s, "PAYLOAD_HEAD", head);
        s.push('\n');
        emit_const_array(&mut s, "PAYLOAD_TAIL", tail);
        s.push('\n');

        s.push_str(&format!("/// Length of {} in bytes.\n", "PAYLOAD_HEAD"));
        s.push_str(&format!("pub const HEAD_LEN: usize = {head_len};\n\n"));
        s.push_str(&format!("/// Length of {} in bytes.\n", "PAYLOAD_TAIL"));
        s.push_str(&format!("pub const TAIL_LEN: usize = {tail_len};\n\n"));

        s.push_str("/// Offset of the flags value byte(s) within the assembled payload.\n");
        s.push_str(&format!(
            "pub const FLAGS_VALUE_OFFSET: usize = {flags_value_offset};\n\n"
        ));
        s.push_str(
            "/// Inner COSE_Key encoded size for ECC-P384 (`public_key_size` field value).\n",
        );
        s.push_str(&format!(
            "pub const PUBLIC_KEY_INNER_SIZE: u16 = {public_key_inner_size};\n\n"
        ));

        s.push_str(
            "/// Offset of the attested public key X coordinate hole within `PAYLOAD_HEAD`.\n",
        );
        s.push_str(&format!("pub const PK_X_OFFSET: usize = {pk_x_head};\n\n"));
        s.push_str(
            "/// Offset of the attested public key Y coordinate hole within `PAYLOAD_HEAD`.\n",
        );
        s.push_str(&format!("pub const PK_Y_OFFSET: usize = {pk_y_head};\n\n"));
        s.push_str("/// Offset of the app_uuid hole within `PAYLOAD_TAIL`.\n");
        s.push_str(&format!(
            "pub const APP_UUID_OFFSET: usize = {app_uuid_tail};\n\n"
        ));
        s.push_str("/// Offset of the report_data hole within `PAYLOAD_TAIL`.\n");
        s.push_str(&format!(
            "pub const REPORT_DATA_OFFSET: usize = {report_data_tail};\n\n"
        ));
        s.push_str("/// Offset of the vm_launch_id hole within `PAYLOAD_TAIL`.\n");
        s.push_str(&format!(
            "pub const VM_LAUNCH_ID_OFFSET: usize = {vm_launch_id_tail};\n"
        ));
        s
    }

    fn emit_const_array(out: &mut String, name: &str, data: &[u8]) {
        out.push_str(&format!(
            "/// {name} template (sanitized; `0x5F` marks patchable holes).\n"
        ));
        out.push_str(&format!("pub const {name}: [u8; {}] = [\n", data.len()));
        for chunk in data.chunks(16) {
            out.push_str("    ");
            for (i, b) in chunk.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&format!("0x{:02X}", b));
            }
            out.push_str(",\n");
        }
        out.push_str("];\n");
    }

    fn output_path() -> PathBuf {
        // gen lives at fw/core/crypto/key-report/gen/, template goes
        // to fw/core/crypto/key-report/src/template.rs.
        let manifest = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest)
            .parent()
            .expect("parent dir")
            .join("src")
            .join("template.rs")
    }
}
