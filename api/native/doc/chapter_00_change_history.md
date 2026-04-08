# Change History


| Date       | Description                                               &nbsp; |
| ---------- | ---------------------------------------------------------------- |
| 04/02/2025 | Document Created                                                 |
| 04/10/2025 | Integrated feedback from Bryan Kelly                             |
| 04/29/2025 | Integrated feedback from Rajesh Gali                             |
| 05/01/2025 | Added API to retrieve certificate chains                         |
|            | Added API to provision partition owner certificate               |
|            | Added Key property to retrieve masked key                        |
|            | Added Session kind support                                       |
|            | Renamed device API to partition API                              |
| 05/12/2025 | Fixed parameter type for partition get API                       |
|            | Fixed parameter name for partition get path API                  |
| 12/09/2025 | Updated algorithm parameter for AES CBC                          |
|            | Added data unit length param to algorithm parameter for AES XTS  |
| 04/02/2026 | Replaced `azihsm_part_get_path` with `azihsm_part_get_info`     |
|            | Added `azihsm_part_info` structure with API revision range       |
|            | Added `api_rev` parameter to `azihsm_part_open`                 |
|            | Removed `api_rev` parameter from `azihsm_sess_open`             |
|            | Added `AZIHSM_STATUS_UNSUPPORTED_API_REVISION` error code       |

\pagebreak