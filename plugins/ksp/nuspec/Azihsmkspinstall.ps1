# This script places azihsmksp library in system32, and calls regsvr32 on library

$provider_name = "Microsoft Azure Integrated HSM Key Storage Provider"
$azihsmksp_library_name = "azihsmksp.dll"
$symcrypt_library_name = "symcrypt.dll"

if (!(Test-Path "$PWD\$azihsmksp_library_name")) {
    Write-Host "$azihsmksp_library_name Not Found. Install Failed"
    throw "$azihsmksp_library_name not installed"
}

if (!(Test-Path "$PWD\$symcrypt_library_name")) {
    Write-Host "$symcrypt_library_name Not Found. Install Failed"
    throw "$symcrypt_library_name not installed"
}

# If azihsmksp provider already exists, try unregister
$output = Invoke-Expression -Command "certutil -csplist"
if ($output -like "*$provider_name*") {
    if (Test-Path "$env:systemroot\System32\$azihsmksp_library_name") {
        Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s","/u","$env:systemroot\System32\$azihsmksp_library_name" -NoNewWindow -Wait
    }
}

# Copy azihsmksp and symcrypt to system32, even if they already exist
Copy-Item "$PWD\$azihsmksp_library_name" -Destination "$env:systemroot\System32\$azihsmksp_library_name" -Force
Copy-Item "$PWD\$symcrypt_library_name" -Destination "$env:systemroot\System32\$symcrypt_library_name" -Force

# Register library NCRYPT provider
$regsvrp = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s","$env:systemroot\System32\$azihsmksp_library_name" -NoNewWindow -Wait -PassThru
if($regsvrp.ExitCode -ne 0) {
    Write-Host "regsvr32 exit code: $($regsvrp.ExitCode)"
}
