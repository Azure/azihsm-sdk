// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_mbor_types::DdiGetApiRevCmdReq;
use azihsm_ddi_mbor_types::DdiGetApiRevCmdResp;
use azihsm_ddi_mbor_types::DdiGetApiRevReq;
use azihsm_ddi_mbor_types::DdiOp;
use azihsm_ddi_mbor_types::DdiReqHdr;
use azihsm_ddi_sock::DdiSock;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap_or_else(|| "vsock://4:1234".to_owned());
    let count = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|error| format!("invalid request count: {error}"))?
        .unwrap_or(1);
    if count == 0 {
        return Err("request count must be greater than zero".into());
    }
    if args.next().is_some() {
        return Err("usage: azihsm_ddi_sock_get_api_rev [ENDPOINT] [COUNT]".into());
    }

    let dev = DdiSock::default().open_dev(&endpoint)?;
    let req = DdiGetApiRevCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetApiRev,
            sess_id: None,
            rev: None,
        },
        data: DdiGetApiRevReq {},
        ext: None,
    };

    for index in 1..=count {
        let resp: DdiGetApiRevCmdResp = dev.exec_op_mbor(&req, &mut None)?;
        if count == 1 {
            println!(
                "GetApiRev succeeded: min={}.{} max={}.{}",
                resp.data.min.major, resp.data.min.minor, resp.data.max.major, resp.data.max.minor
            );
        } else {
            println!(
                "GetApiRev {index}/{count} succeeded: min={}.{} max={}.{}",
                resp.data.min.major, resp.data.min.minor, resp.data.max.major, resp.data.max.minor
            );
        }
    }
    Ok(())
}
