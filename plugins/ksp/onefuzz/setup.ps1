# This is a OneFuzz setup script. It performs one-time setups needed for the
# KSP fuzzing tests.
#
# When OneFuzz jobs are submitted for the KSP, this script will be copied into
# the drop directory alongside the KSP fuzzing targets, the AZIHSM KSP DLL, and
# the OneFuzz config file. OneFuzz will execute this script before starting any
# fuzz tests.
#
# See the documentation here:
# https://eng.ms/docs/cloud-ai-platform/azure-edge-platform-aep/aep-security/epsf-edge-and-platform-security-fundamentals/the-onefuzz-service/onefuzz/faq/windowsdockedv2/setupps1
#
# This is necessary for the KSP fuzzing tests, because we need to register the
# KSP DLL as a CNG Provider using the `regsvr32`, in order for the fuzzing
# tests to find the KSP via `NCryptOpenStorageProvider()`.

$script_dir = "$PSScriptRoot"
$ksp_dll_name = "azihsmksp.dll"

# Tell the PowerShell script to immediately stop upon any errors. This allows
# us to see some of the output from this script in any error/failure messages
# in the OneFuzz UI.
#
# See this page for more information on `$ErrorActionPreference`:
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables
$ErrorActionPreference = "Stop"

# Main function.
function main
{
    # search for the KSP DLL
    $dll = Get-ChildItem -Path "$script_dir" -Filter "$ksp_dll_name" -Recurse | Select-Object -First 1
    if ($dll -eq $null)
    {
        Write-Error "Failed to find the KSP DLL (`"$ksp_dll_name`") within: `"$script_dir`"."
        return 1
    }
    $dll = $dll.FullName
    Write-Host "Found KSP DLL: `"$dll`"."

    # copy the DLL to the system32 directory, so the fuzzing tests can find it
    $dll_dst = "C:\Windows\System32\$ksp_dll_name"
    Copy-Item -Path "$dll" -Destination "$dll_dst"
    if (!(Test-Path -Path "$dll_dst"))
    {
        Write-Error "Failed to copy the KSP DLL (`"$dll`") to system32 (`"$dll_dst`")."
        return 2
    }
    Write-Host "Copied DLL (`"$dll`") to system32: `"$dll_dst`"."

    return 0
}

$retcode = main @args
exit $retcode

