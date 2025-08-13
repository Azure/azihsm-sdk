# build.ps1

# Set script variables
$root = "$PSScriptRoot"
$dll_name = "azihsmksp.dll"
$dll_dst = "C:\Windows\System32\$dll_name"
$CargoFlags = "--features mock,table-4,expose-symbols" -split " "

# ----------------------------- Helper Functions ----------------------------- #
# Attempts to locate the most recent `azihsmksp.dll` that was built within the
# given directory. The path to the newest `azihsmksp.dll` is returned.
# 
# This is used when building the KSP DLL and installing it.
function find_dll
{
    # define function parameters
    param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $path
    )

    # recursively find all `azihsmksp.dll` files
    $files = Get-ChildItem -Path "$path" -Filter "$dll_name" -Recurse

    # if no files were found, return NULL
    if ($files.Count -eq 0)
    {
        Write-Error "Cannot find ``$dll_name``. The build must have failed."
        return $null
    }

    # otherwise, sort the files by 'LastWriteTime' and choose the newest
    $newest = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    # if there is more than one DLL, warn the user that we're choosing the most
    # recently-modified DLL
    if ($files.Count -gt 1)
    {
        $msg = "Multiple DLLs (``$dll_name``) were found within ``$path``."
        $msg = "$msg Selected the most recent one: ``$newest``."
        Write-Warning "$msg"
    }

    return $newest.FullName
}

# Takes the path to the KSP DLL and installed it to System32.
function install_dll([string] $dll_src)
{
    # is the DLL already installed? If so, we want to delete the old version
    if (Test-Path "$dll_dst")
    {
        Write-Host "Found old copy of DLL at: `"$dll_dst`". Deleting..."
        Remove-Item -Path "$dll_dst"
    }

    # copy the DLL to the destination, then make sure the file arrived
    Write-Host "Copying DLL to: `"$dll_dst`"."
    Copy-Item "$dll_src" -Destination "$dll_dst"
    if (!(Test-Path $dll_dst))
    {
        Write-Error "Cannot find DLL at `"$dll_dst`". " `
                    "The copy must have failed. " `
                    "Do you have permissions to access this location?"
        return $false
    }
    return $true
}


# ------------------------------- Runner Code -------------------------------- #
# Main function.
function main
{
    param(
        [Parameter(Position=0)]
        [ValidateSet("dll", "compile_tests", "test", "test_prefix", "all")]
        [string]$Target = "all",
    
        [Parameter(Position=1)]
        [string]$Prefix,
    
        [Parameter(Position=2)]
        [string]$TestCaseName
    )
    
    switch ($Target) {
        "dll" {
            # build the DLL
            cargo build @CargoFlags
    
            # find the DLL within the target directory
            $target_dir = "$root\target"
            $dll_source = find_dll "$target_dir"
            if ($dll_source -eq $null) {
                Write-Error "Could not find `"$dll_name`" in `"$target_dir`". " `
                            "The build may have failed."
                return
            }

            # install the DLL to System32
            $success = install_dll "$dll_source"
            if ($success -eq $false) {
                return
            }

            # print a final success message
            $msg = "Installation complete. If you have not done so yet,"
            $msg = "$msg run this one-time command to register the DLL with the OS:"
            Write-Host "$msg"
            Write-Host ""
            Write-Host "    regsvr32 $dll_dst"
            Write-Host ""
        }
        "compile_tests" { cargo test --no-run @CargoFlags }
        "test" { 
            cargo test --no-run @CargoFlags
            if (-not $Prefix) {
                Write-Error "Prefix parameter is required for test_prefix target"
                $Prefix = "test"
            }
            Get-ChildItem ".\target\debug\deps\$($Prefix)_*.exe" | ForEach-Object {
                Write-Host "Running $($_.FullName)"
                if ($TestCaseName) {
                    & $_.FullName --test-threads=1 --test $TestCaseName -- --nocapture
                } else {
                    & $_.FullName --test-threads=1
                }
            }
        }
        "all" {
            cargo build @CargoFlags
            cargo test --no-run @CargoFlags
        }
    }
}

# temporary CD into the ksp directory before calling `main`, so no matter where
# we're calling this script from, it runs from the same location
pushd "$root"
main @args
popd

