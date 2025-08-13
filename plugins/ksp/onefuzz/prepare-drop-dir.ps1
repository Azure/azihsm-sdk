# This script is used by the OneFuzz pipeline to submit the KSP fuzzing tests
# for continuous fuzzing.
#
# Unlike similar scripts in this repository (such as
# `api/onefuzz/prepare-drop-dir.sh`), this script does *not* build the DLL and
# fuzzing tests from source. It instead expects them to have been already
# built, and locates them with the provided `-CargoTargetDir` script argument.
#
# This script is set up this way because a PowerShell script already exists
# that builds the KSP DLL and fuzzing tests:
# `.pipelines/scripts/run-azihsm-ksp-fuzz-tests.ps1`. This script should be
# executed prior to executing this script, in order for the drop directory to
# be created successfully. (This is what the OneFuzz pipeline does.)

$onefuzz_dir = "$PSScriptRoot"
$ksp_dir = Split-Path -Path "$onefuzz_dir" -Parent
$ksp_dll_name = "azihsmksp.dll"
$setup_env_script_name = "setup-env.ps1"

# Helper function that runs the KSP `setup-env.ps1`, which ensures the shell
# can access tools like `dumpbin`, which are used in this script.
function setup_env
{
    # look for the environment-setup script, and run it
    $setup_env_script_path = "$ksp_dir\$setup_env_script_name"
    if (!(Test-Path "$setup_env_script_path"))
    {
        Write-Error "Could not find environment-setup script at: $setup_env_script_path"
        return 1
    }
    . "$setup_env_script_path" "fuzz"
    $setup_result = $LastExitCode
    if ($setup_result -ne 0)
    {
        Write-Error "Setup failed."
        return 2
    }

    return 0
}

# Helper function used to retrieve the PDB file corresponding to the provided
# binary. The path to the PDB file is returned, or `$null` is returned if one
# isn't found.
function find_pdb
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$BinaryPath
    )

    # get the expected name & path of the PDB file we're looking for
    $pdb_src = [System.IO.Path]::ChangeExtension("$BinaryPath", ".pdb")
    if (!(Test-Path -Path "$pdb_src" -PathType "Leaf"))
    { return $null }
    return "$pdb_src"
}

# Helper function used to find the fuzzing binaries and the AZIHSM KSP DLL in
# the cargo target directory. Returns a file path, or `$null`.
function find_binary
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$CargoTargetDir,
        [Parameter(Mandatory=$true)]
        [string]$BinaryName
    )

    # search for the binary within the target directory; return early if an
    # binary was not found
    $binaries = @(Get-ChildItem -Path "$CargoTargetDir" -Filter "$BinaryName" -Recurse)
    if ($binaries.Length -eq 0)
    {
        $msg = "Could not find a binary matching the name: `"$BinaryName`"."
        Write-Error "$msg"
        return $null
    }

    # if more than one binary was found, choose one, but warn the user that
    # multiple were found
    if ($binaries.Length -gt 1)
    {
        $msg = "Found more than one binary matching the name: `"$BinaryName`":`n"
        foreach ($binary in $binaries)
        {
            $binary_name = $binary.FullName
            $msg = "${msg} - $binary_name`n"
        }
        $msg = "${msg}Selecting the first match..."
        Write-Warning "$msg"
    }

    # select the first entry in the list as the fuzzing executable, and
    # copy it into the drop directory
    return $binaries[0].FullName
}

# Searches for a given DLL on the system PATH. Returns the first-found file
# path, or `$null` if not found.
function find_dll_path
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    
    # split the PATH environment variable and search through each one in a loop
    $dirs = $env:PATH -split ";"
    foreach ($dir in $dirs)
    {
        $path = Join-Path -Path "$dir" -ChildPath "$Name"
        if (Test-Path -Path "$path" -PathType "Leaf")
        { return "$path" }
    }
    return $null
}

# Takes in the path to a Windows binary and attempts to generate a list of DLLs
# that the binary depends on. A list of DLL file paths is returned, of `$null`
# on failure or error.
function find_binary_dependencies
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$BinaryPath
    )
    
    # make sure `dumpbin` is accessible in this shell instance
    $dumpbin_cmd = Get-Command "dumpbin.exe"
    if ($dumpbin_cmd -eq $null)
    {
        Write-Error "Could not find `"dumpbin.exe`". Please ensure it is installed and accessible from the shell."
        return $null
    }
    $dumpbin = $dumpbin_cmd.Source

    # invoke `dumpbin` to get a list of all DLLs the binary depends on
    $output = & $dumpbin /dependents "$BinaryPath"
    $dlls = $output | Select-String -Pattern "\.dll"

    # for each of the DLLs names, we want to locate where it is on the shell's
    # path. Iterate through each and invoke another helper function
    $result = @()
    foreach ($dll_name in $dlls)
    {
        $dll_name = "$dll_name".TrimStart().TrimEnd()
        $dll_path = find_dll_path -Name "$dll_name"

        # if the DLL is in the System32 directory (except for symcrypt!), we'll
        # assume that OneFuzz will set these up for us; skip them
        if (("$dll_path" -like "*\Windows\System32\*") -and
           !("$dll_path" -like "*symcrypt*"))
        { continue }

        # if the DLL couldn't be found, skip it
        if ($dll_path -eq $null)
        { continue }

        # if the DLL is already in the list, skip to the next iteration
        if ($result -contains "$dll_path")
        { continue }

        # otherwise, add the DLL path to the list
        $result += @("$dll_path")

        # recursively look for any dependencies *this* DLL has
        $child_dll_paths = find_binary_dependencies -BinaryPath "$dll_path"
        foreach ($child_dll_path in $child_dll_paths)
        {
            # only add this dependency if it's not already in the list
            if ($result -contains "$child_dll_path")
            { continue }
            $result += @("$child_dll_path")
        }
    }

    return $result
}

# Helper function that takes a list of dependency DLL file paths and copies
# them into the drop directory.
#
# Returns 0 on success, and non-zero on failure.
function copy_dependencies_to_drop_dir
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$DropDirectory,
        [Parameter(Mandatory=$true)]
        [string[]]$Dependencies
    )

    foreach ($dep_path in $Dependencies)
    {
        $dep_name = Split-Path -Path "$dep_path" -Leaf
        $dep_dst = Join-Path -Path "$DropDirectory" -ChildPath "$dep_name"

        # was the file already copied before? If so, skip it
        if (Test-Path -Path "$dep_dst" -PathType "Leaf")
        { continue }

        # copy the DLL into the drop directory
        Copy-Item -Path "$dep_path" -Destination "$dep_dst" -Force
        Write-Host "Copied dependency DLL (`"$dep_path`") to drop directory: `"$dep_dst`"."

        # if the copy failed, return early
        if (!(Test-Path -Path "$dep_dst" -PathType "Leaf"))
        {
            Write-Error "Failed to copy dependency DLL (`"$dep_path`") to drop directory."
            return 1
        }
    }

    return 0
}

function main
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$FuzzPath,
        [Parameter(Mandatory=$true)]
        [string]$DropDirectory,
        [Parameter(Mandatory=$true)]
        [string]$CargoTargetDir
    )

    # setup the shell environment
    $setup_env_result = setup_env
    if ($setup_env_result -ne 0)
    {
        Write-Error "Failed to set up shell environment."
        return 1
    }
    
    # make sure cargo is installed
    $cargo = Get-Command "cargo.exe" | Select-Object -ExpandProperty Path
    if ($cargo -eq  $null)
    {
        Write-Host "Error: could not find cargo. Please ensure it is installed."
        return 2
    }

    # make sure the cargo target directory exists
    if (!(Test-Path "$CargoTargetDir" -PathType Container))
    {
        Write-Warning "The provided CargoTargetDir does not point to a valid directory."
        Write-Warning "Please have it point to a cargo target directory containing the built KSP DLL and fuzzing tests."
        return 2
    }

    # if the drop directory doesn't exist, create it
    if (!(Test-Path "$DropDirectory"))
    { New-Item -Path "$DropDirectory" -ItemType "Directory" }

    # if the drop directory already contains files, complain and exit
    $children = Get-ChildItem -Path "$DropDirectory"
    if ($children.Count -gt 0)
    {
        Write-Error "The drop directory is not empty. Please empty it before proceeding."
        return 3
    }

    # -------------------------- Fuzzing Test Setup -------------------------- #
    # get a listing of all the fuzz targets via `cargo fuzz list`, locate each
    # executable, and copy it into the drop directory
    pushd "$FuzzPath"
    & "$cargo" "fuzz" "list" | Tee-Object -Variable output
    $fuzz_targets = "$output" -split "\s+"
    foreach ($target in $fuzz_targets)
    {
        # skip any fuzzing targets that don't begin with "fuzz_*"
        if (!($target -like "fuzz_*"))
        { continue }

        # search for the executable within the target directory; return early
        # if an executable was not found
        $binary_src = find_binary -CargoTargetDir "$CargoTargetDir" -BinaryName "${target}.exe"
        if ($binary_src -eq $null)
        {
            Write-Error "Please ensure the fuzzing tests and DLL have already been built for fuzzing."
            Write-Error "$msg"
            return 4
        }

        # copy the binary into the drop directory
        $binary_dst = Join-Path -Path "${DropDirectory}" -ChildPath "${target}.exe"
        Copy-Item -Path "$binary_src" -Destination "$binary_dst" -Force
        Write-Host "Copied fuzzing test (`"$binary_src`") to drop directory (`"$binary_dst`")."

        # if the copy failed, return early
        if (!(Test-Path -Path "$binary_dst" -PathType "Leaf"))
        {
            Write-Error "Failed to copy executable to drop directory: `"$binary_src`"."
            return 5
        }

        # search for the corresponding PDB file for the binary; this is needed
        # too, for Windows OneFuzz jobs
        $pdb_src = find_pdb -BinaryPath "$binary_src"
        if ($pdb_src -eq $null)
        {
            $msg = "Failed to find PDB for binary: `"$binary_src`"."
            $msg = "$msg Please ensure the fuzzing tests and DLL have already been built for fuzzing, with PDB files."
            return 6
        }

        # copy the PDB into the drop directory
        $pdb_dst = Join-Path -Path "${DropDirectory}" -ChildPath "${target}.pdb"
        Copy-Item -Path "$pdb_src" -Destination "$pdb_dst" -Force
        Write-Host "Copied fuzzing test PDB (`"$pdb_src`") to drop directory (`"$pdb_dst`")."

        # if the copy failed, return early
        if (!(Test-Path -Path "$pdb_dst" -PathType "Leaf"))
        {
            Write-Error "Failed to copy executable PDB to drop directory: `"$pdb_src`"."
            return 7
        }

        # look for any dependencies this executable has, and copy each of them
        # to the drop directory
        $deps = @(find_binary_dependencies -BinaryPath "$binary_src")
        if ($deps -eq $null)
        {
            Write-Error "Failed to find and copy dependency DLLs for binary: `"$binary_src`"."
            return 8
        }
        $deps_copy_result = copy_dependencies_to_drop_dir -DropDirectory "$DropDirectory" -Dependencies $deps
        if ($deps_copy_result -ne 0)
        {
            return 9
        }
    }
    popd # return from fuzz directory (`$FuzzPath`)
    
    # ------------------------- AZIHSM KSP DLL Setup ------------------------- #
    # search for the AZIHSM KSP DLL within the cargo target directory. If none
    # were found, return early with an error
    $dll_src = find_binary -CargoTargetDir "$CargoTargetDir" -BinaryName "$ksp_dll_name"
    if ($dll_src -eq $null)
    {
        Write-Error "Please ensure the fuzzing tests and DLL have already been built for fuzzing."
        return 10
    }
    
    # copy the DLL into the drop directory
    $dll_dst = "${DropDirectory}\$ksp_dll_name"
    Copy-Item -Path "$dll_src" -Destination "$dll_dst" -Force
    Write-Host "Copied AZIHSM KSP DLL (`"$dll_src`") to drop directory (`"$dll_dst`")."

    # if the copy failed, return early
    if (!(Test-Path -Path "$dll_dst" -PathType "Leaf"))
    {
        Write-Error "Failed to copy AZIHSM KSP DLL to drop directory: `"$dll_src`"."
        return 11
    }

    # search for the corresponding PDB file for the DLL; this is needed
    # too, for Windows OneFuzz jobs
    $pdb_src = find_pdb -BinaryPath "$dll_src"
    if ($pdb_src -eq $null)
    {
        $msg = "Failed to find PDB for AZIHSM KSP DLL: `"$dll_src`"."
        $msg = "$msg Please ensure the fuzzing tests and DLL have already been built for fuzzing, with PDB files."
        return 12
    }
    # copy the PDB into the drop directory
    $ksp_pdb_name = [System.IO.Path]::ChangeExtension("$ksp_dll_name", ".pdb")
    $pdb_dst = "${DropDirectory}\$ksp_pdb_name"
    Copy-Item -Path "$pdb_src" -Destination "$pdb_dst" -Force
    Write-Host "Copied AZIHSM KSP PDB (`"$pdb_src`") to drop directory (`"$pdb_dst`")."
    # if the copy failed, return early
    if (!(Test-Path -Path "$pdb_dst" -PathType "Leaf"))
    {
        Write-Error "Failed to copy AZIHSM KSP PDB to drop directory: `"$pdb_src`"."
        return 13
    }

    # look for any dependencies the AZIHSM KSP DLL has, and copy each of them
    # to the drop directory
    $deps = @(find_binary_dependencies -BinaryPath "$dll_src")
    if ($deps -eq $null)
    {
        Write-Error "Failed to find and copy dependency DLLs for AZIHSM KSP DLL: `"$dll_src`"."
        return 14
    }
    $deps_copy_result = copy_dependencies_to_drop_dir -DropDirectory "$DropDirectory" -Dependencies $deps
    if ($deps_copy_result -ne 0)
    {
        return 15
    }
    
    # ------------------------- OneFuzz Config Setup ------------------------- #
    # ensure the OneFuzzConfig file can be found
    $onefuzz_config_src = "${onefuzz_dir}\OneFuzzConfig.json"
    if (!(Test-Path -Path "$onefuzz_config_src" -PathType "Leaf"))
    {
        Write-Error "Could not find OneFuzz config file at: `"$onefuzz_config_src`"."
        return 16
    }

    # copy the OneFuzzConfig file into the drop directory
    $onefuzz_config_dst = "${DropDirectory}\OneFuzzConfig.json"
    Copy-Item -Path "$onefuzz_config_src" -Destination "$onefuzz_config_dst" -Force
    Write-Host "Copied OneFuzz config file (`"$onefuzz_config_src`") to drop directory (`"$onefuzz_config_dst`")."
    
    # if the copy failed, return early
    if (!(Test-Path -Path "$onefuzz_config_dst" -PathType "Leaf"))
    {
        Write-Error "Failed to copy OneFuzz config file to drop directory: `"$onefuzz_config_src`"."
        return 17
    }

    # ----------------------------- Setup Script ----------------------------- #
    # OneFuzz supports an optional `setup.ps1` script, which can be included in
    # the drop directory. If included, it will be executed (with admin
    # privileges) prior to beginning fuzzing.
    #
    # We need a `setup.ps1` script for the KSP fuzzing tests, because we need
    # to perform a one-time registration of the KSP DLL as a CNG Provider
    # (using `regsvr32`). So, we'll copy it into the drop directory here.
    $setup_src = Join-Path -Path "${onefuzz_dir}" -ChildPath "setup.ps1"
    if (!(Test-Path -Path "$setup_src" -PathType "Leaf"))
    {
        Write-Error "Could not find OneFuzz setup script at: `"$setup_src`"."
        return 18
    }

    # copy the setup script into the drop directory
    $setup_dst = Join-Path -Path "${DropDirectory}" -ChildPath "setup.ps1"
    Copy-Item -Path "$setup_src" -Destination "$setup_dst" -Force
    Write-Host "Copied OneFuzz setup script (`"$setup_src`") to drop directory (`"$setup_dst`")."
    
    # if the copy failed, return early
    if (!(Test-Path -Path "$setup_dst" -PathType "Leaf"))
    {
        Write-Error "Failed to copy OneFuzz setup script to drop directory: `"$setup_src`"."
        return 19
    }
    
    Write-Output "$DropDirectory"
    return 0
}

$retcode = main @args
exit $retcode

