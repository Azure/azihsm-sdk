# Running KeyGuard tests

Microsoft Software Key Storage Provider is the default KSP on Windows. In order to maximize Manticore KSP's compatibility
with MS KSP, we seek to run Manticore KSP with MS KSP's tests and fuzzing targets. In order to do this, follow these steps below.

## 0. Build Manticore KSP
Instructions can be found under `plugins/ksp`. KeyGuard tests have only been verified with 'mock' configuration.

## 1. Get Access to Windows OS Repo
You can follow instructions [here](https://eng.ms/docs/more/azure-devops-support-azurewindows/accessandsecurity/user-access-policies/user-access-policies). (You are probably in Cloud+AI under Scott Guthree.) You should only need R/O access.

## 2. Create a VM using Hyper-V and set up testing environment
Follow the steps outlined [here](https://www.osgwiki.com/wiki/Key_Guard/dev#Create_the_VM).

The path used in document, `\\winbuilds\release\rs_onecore_ens_id` is no longer updated. You can use VM image from
```
\\winbuilds\release\rs_main\<build>\amd64fre\vhdx\vhdx_client_enterprise_en-us_vl
```
Recommended to use build at least one or two days old. Most recent build may not have finished yet, and might not have vhdx or testing binaries.

You need to follow steps through "Apply Registry Settings" step to run KeyGuard tests, even if you're only testing against Manticore KSP.

## 3. Clone the OS repo
Follow [this guide](https://www.osgwiki.com/wiki/GVFS_Clone) to install GVFS and clone the OS repo on your dev machine.

You can clone off of branch `main`.

Open a new [Razzle](https://www.osgwiki.com/wiki/Razzle) shell.

## 4. Apply patch and build testing binary
Copy `manticore_ksp_tests.patch` to the base level of the OS repo, and apply it by doing

``` powershell
git apply --whitespace=fix --verbose manticore_ksp_tests.patch
```

There may be errors if GVFS has not fully hydrated the files that need to be patched. I fixed this by making small whitespace edits to files that were not being found by the apply patch step. You could also try building in the directory (run `bcp`) before applying patch.

Afterwards, build `ksptests.dll` by navigating to `os\src\onecore\ds\security\cryptoapi\ncrypt\test\storage` and running `bcp` on the Razzle shell. (`bcp` rebuilds current directory and any parent directories that are dependencies. [Build.exe documentation](https://www.osgwiki.com/wiki/Build.exe))

The resulting `ksptests.dll` will appear in a directory like:
```
os\bin\amd64fre\UnitTest\cng\ksptests.dll
```

## 5. Run tests
KSP tests are run by the TAEF framework, which we will need to grab from a Windows build.
From the build release directory, browse through builds and look under paths similar to this:
```
\\winbuilds\release\rs_main\<build>\amd64fre\bin\wextest\cue\TestExecution\minte
```
If possible, use the same build as the test VM.

Also find directory `cfg` from
```
os\src\onecore\ds\security\cryptoapi\ncrypt\test\storage\legacyKSPtests
```

Copy `ksptests.dll`, `minte`, and `cfg` to your testing directory on your test VM image. It should look like this:

```
 Directory of c:\ksp_testing

05/19/2025  07:11 PM    <DIR>          .
05/15/2025  10:38 AM    <DIR>          cfg
05/15/2025  11:11 AM         2,035,360 ksptests.dll
05/15/2025  10:30 AM    <DIR>          MinTe
               1 File(s)      2,035,360 bytes
               3 Dir(s)  42,063,454,208 bytes free
```

Run the following command to run tests:
```
.\minte\te.exe .\ksptests.dll /select:"@Name='KSPTestNS::KSPTest::TestNCrypt*'"
```

For more information about running KeyGuard tests, see [here](https://www.osgwiki.com/wiki/Key_Guard/dev#Running_Tests).

# Expected test failures and explanation

Updated 5/29/2025

There are some failures that effect most/all tests:
| Issue | Missing task item |
| ----- | ----- |
| Named keys not supported | [Task item](https://msazure.visualstudio.com/One/_workitems/edit/31480167) |
| NCryptImportKey/NCryptGeneratePersistedKey requires DO_NOT_FINALIZE_FLAG | [Task item](https://msazure.visualstudio.com/One/_workitems/edit/31988366) |

To mitigate the above issues for testing, you can make the following temporary changes:
- Remove the check for NCRYPT_DO_NOT_FINALIZE_FLAG in azihsm_create_persisted_key
- Remove the key_name.is_null check in azihsm_create_persisted_key
- Remove the NCRYPT_DO_NOT_FINALIZE_FLAG check in azihsm_import_key

If everything is set up correctly, and mitigations are implemented for the above issues, then you will see 9 failures out of 22 tests (one for each NCrypt API):
| Test | Missing task item |
| ----- | ----- |
| [NCryptEnumKeys](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptenumkeys) | Currently not supported. Needs to be supported as part of named keys. [Task item](https://msazure.visualstudio.com/One/_workitems/edit/31480167). |
| [NCryptEnumAlgorithms](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptenumalgorithms) | Currently not supported. [Task item](https://msazure.visualstudio.com/One/_workitems/edit/32327964). |
| [NCryptEncrypt](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptencrypt) | Some tests use `NCRYPT_NO_PADDING_FLAG`, which Manticore KSP does not support. Furthermore, we only support OAEP. This is expected; we require padding for RSA encryption. |
| [NCryptDeriveKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptderivekey) | BCRYPT_KDF_HMAC only allows these flags for the parameter list: KDF_HASH_ALGORITHM, KDF_SECRET_APPEND, KDF_SECRET_PREPEND, KDF_USE_SECRET_AS_HMAC_KEY_FLAG. Furthermore, tests are failing due to empty parameter list being passed to Manticore KSP. We should support null paramters and fallback to defaults. [Task item](https://msazure.visualstudio.com/One/_workitems/edit/32275123). |
| [NCryptGetProperty](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptgetproperty) | Failure due to some tests calling this API without calling `NCryptSetProperty` first. [Task item](https://msazure.visualstudio.com/One/_workitems/edit/32963277). |
| [NCryptIsAlgSupported](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptisalgsupported) | Currently not supported. [Task item](https://msazure.visualstudio.com/One/_workitems/edit/32327964). |
| [NCryptNotifyChangeKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptnotifychangekey) | Not supported. I don't think supporting this API is necessary. |
| [NCryptFinalizeKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfinalizekey) | Manticore is requiring FinalizeKey in cases where it shouldn't. [Task item](https://msazure.visualstudio.com/One/_workitems/edit/31988366). |
| [NCryptFreeObject](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfreeobject) | Calling NCryptFreeObject on NCRYPT_KEY_HANDLE always results in fault. [Task item](https://msazure.visualstudio.com/One/_workitems/edit/32988460) |
