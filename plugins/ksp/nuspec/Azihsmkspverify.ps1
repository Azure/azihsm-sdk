# This script verifies driver and provider are installed, using pnputil and certutil

$driver_inf_name = "azihsmvf.inf"
$provider_name = "Microsoft Azure Integrated HSM Key Storage Provider"
$azihsmksp_library_name = "azihsmksp.dll"
$symcrypt_library_name = "symcrypt.dll"

# Verify driver exists with Get-WindowsDriver
$driver_inf = (Get-WindowsDriver -Online | Where-Object { $_.OriginalFileName -like "*$driver_inf_name*" }).Driver
if ($driver_inf -eq $null) {
    Write-Host "Driver '$driver_inf_name' Not Found with Get-WindowsDriver."
    throw "Driver '$driver_inf_name' Not Found with Get-WindowsDriver."
}

# Verify KSP dll exists in system32
if (!(Test-Path "$env:systemroot\System32\$azihsmksp_library_name")) {
    Write-Host "$azihsmksp_library_name Not Found in system32."
    throw "$azihsmksp_library_name Not Found in system32."
}

# Verify symcrypt dll exists in system32
if (!(Test-Path "$env:systemroot\System32\$symcrypt_library_name")) {
    Write-Host "$symcrypt_library_name Not Found in system32."
    throw "$symcrypt_library_name Not Found in system32."
}

# Verify provider exists in certutil
$certutil_output = Invoke-Expression -Command "certutil -csplist"
if (!($certutil_output -like "*$provider_name*")) {
    Write-Host "Provider '$provider_name' Not Found with certutil."
    throw "Provider '$provider_name' Not Found with certutil."
}
