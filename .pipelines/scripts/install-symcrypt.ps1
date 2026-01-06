# This script installs SymCrypt to a specified location.

# SymCrypt configuration (the null fields are set below in the main function).
$global:symcrypt_lib_path_name = "SYMCRYPT_LIB_PATH"
$global:symcrypt_repo_owner = "microsoft"
$global:symcrypt_repo_name = "SymCrypt"
$global:symcrypt_dll_name = "symcrypt.dll"
$global:symcrypt_version = $null
$global:symcrypt_os = $null
$global:symcrypt_arch = $null
$global:download_path = $null
$global:download_retry_count = 4
$global:install_path = $null

# Defaults
# By default (when the below version variables are set to `$null`), we target
# the latest version of SymCrypt from either GitHub or the internal NuGet feed,
# depending on which installation method is selected.
#
# Example version strings:
#
# - GitHub: "v103.5.1"
# - NuGet: "103.10.0-b39181fb-129971309"
$global:symcrypt_version_default_github = $null
$global:symcrypt_version_default_nuget = $null
$global:symcrypt_nuget_package_name = "Microsoft.SymCrypt"
$global:symcrypt_nuget_source_url = "https://microsoft.pkgs.visualstudio.com/_packaging/SymCrypt.NuGet/nuget/v3/index.json"

# Returns `$true` if environment variables are present that suggest this script
# is running in an ADO pipeline.
function is_running_in_ado_pipeline
{
    if ($env:TF_BUILD)
    { return $true }
    return $false
}

# Takes in a file path and returns its full/absolute path.
function get_full_path
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $item = Get-Item "${Path}"
    return $item.FullName
}

# Builds and returns the GitHub URL to target in order to download the SymCrypt
# release.
function get_github_release_url
{
    $url = "https://api.github.com/repos"
    $url = "${url}/${global:symcrypt_repo_owner}"
    $url = "${url}/${global:symcrypt_repo_name}"
    $url = "${url}/releases"

    # if we're retrieving the latest version, just append "latest"
    if ($global:symcrypt_version -eq "latest" -or
        $global:symcrypt_version -eq $null -or
        $global:symcrypt_version -eq "")
    { $url = "${url}/latest" }
    # otherwise, use the version as a tag and add "tags/" to the URL
    else
    { $url = "${url}/tags/${global:symcrypt_version}" }

    return "$url"
}

# Downloads the SymCrypt release from GitHub and extracts it to the install
# location.
function download_github_release
{
    $url = get_github_release_url

    # --------------------------- Archive Download --------------------------- #
    Write-Host "Pinging Release URL: ${url}"
    $response = Invoke-RestMethod `
                -Uri "${url}" `
                -Headers @{"User-Agent" = "PowerShell"}

    # iterate through the assets and look for one that matches our OS and
    # architecture
    $chosen_asset = $null
    $arch_regex = [Regex]"${global:symcrypt_arch}"
    $os_regex = [Regex]"${global:symcrypt_os}"
    foreach ($asset in $response.assets)
    {
        $name = $asset.name.ToLower().Trim()
        if ($arch_regex.IsMatch($name) -and
            $os_regex.IsMatch($name))
        {
            $chosen_asset = $asset
            Write-Host "Found asset: ${name}"
        }
    }

    # if we never found a matching asset, throw an error
    if ($chosen_asset -eq $null)
    {
        throw "Failed to find a SymCrypt asset matching OS `"${global:symcrypt_os}`" and Architecture `"${global:symcrypt_arch}`"."
    }

    # create the download directory, if it doesn't exist yet
    New-Item -Path "${global:download_path}" -ItemType "directory" -Force

    # grab the asset's download URL and download it
    $download_url = $chosen_asset.browser_download_url
    $fname = $chosen_asset.name
    $global:download_path = get_full_path -Path "${global:download_path}"
    $fpath = Join-Path -Path "${global:download_path}" -ChildPath "${fname}"

    # try downloading the file multiple times, in case intermittent issues are
    # encountered
    $retry_count = $global:download_retry_count
    $attempt = 0
    while ($attempt -lt $retry_count)
    {
        try
        {
            Write-Host "Attempting to download asset from: ${download_url}"
            Invoke-WebRequest -Uri "${download_url}" -OutFile "${fpath}"

            # exit the loop on the first success
            break
        }
        catch
        {
            Write-Warning "Failed to download asset (attempt $($attempt + 1) of $retry_count)."
            $attempt++
            Start-Sleep -Seconds 2
            continue
        }
    }

    # make sure the file was downloaded
    if (!(Test-Path "${fpath}" -PathType Leaf))
    {
        throw "Failed to download SymCrypt asset from: ${download_url}"
    }
    Write-Host "Downloaded asset to: ${fpath}"

    # -------------------------- Archive Extraction -------------------------- #
    # create the install path, if it doesn't already exist
    New-Item -Path "${global:install_path}" -ItemType "directory" -Force
    $global:install_path = get_full_path -Path "${global:install_path}"

    # extract the archive's contents into the install path
    Expand-Archive -Path "${fpath}" -DestinationPath "${global:install_path}" -Force
    Write-Host "Extracted release to: ${global:install_path}"

    # remove the archive file
    Remove-Item -Path "${fpath}" -Force

    # return a path to the directory containing the extracted contents
    return ${global:install_path}
}

# Downloads the SymCrypt release from the internal NuGet feed.
function download_nuget_release
{
    # look for the `nuget.exe` executable. If it's not found, throw an error.
    $nuget_exe = Get-Command "nuget.exe" -ErrorAction Silent
    if ($nuget_exe -eq $null)
    {
        throw "Failed to find ``nuget.exe`` in PATH. Please install NuGet and ensure it's available in PATH."
    }
    $nuget_exe_path = get_full_path -Path $nuget_exe.Path
    Write-Host "Found NuGet executable at: ${nuget_exe_path}"

    # --------------------------- Package Download --------------------------- #
    # put together a list of arguments to pass to `nuget.exe`
    $nuget_args = @(
        "install",
        "$global:symcrypt_nuget_package_name",
        "-Source", "$global:symcrypt_nuget_source_url",
        "-OutputDirectory", "$global:download_path",
        "-Verbosity", "detailed",
        "-NonInteractive",
        "-NoHttpCache",
        "-DirectDownload",
        "-PreRelease"
    )

    # if a version is specified, add it to the arguments
    if ($global:symcrypt_version -ne $null -and $global:symcrypt_version -ne "")
    {
        $nuget_args += @("-Version", "$global:symcrypt_version")
    }

    # try invoking `nuget.exe` multiple times to downoad SymCrypt, in case we
    # encounter any intermittent issues
    $retry_count = $global:download_retry_count
    $attempt = 0
    while ($attempt -lt $retry_count)
    {
        try
        {
            Write-Host "Executing: NuGet with arguments: ``$($nuget_args -join ' ')``"

            $proc = Start-Process -FilePath "$nuget_exe_path" `
                                  -Wait `
                                  -PassThru `
                                  -NoNewWindow `
                                  -ArgumentList "$($nuget_args -join ' ')"
            $nuget_exit_code = $proc.ExitCode

            # if NuGet failed, throw an error
            if ($nuget_exit_code -ne 0)
            {
                throw "NuGet exited with code: ${nuget_exit_code}"
            }

            # exit the loop on the first success
            break
        }
        catch
        {
            Write-Warning "Failed to download asset via NuGet (attempt $($attempt + 1) of $retry_count)."
            $attempt++
            Start-Sleep -Seconds 2
            continue
        }
    }

    # look for the downloaded package
    $package_dir_glob = Join-Path -Path "$global:download_path" -ChildPath "$global:symcrypt_nuget_package_name.*"
    $package_dirs = Get-ChildItem -Path "$package_dir_glob" -Directory
    if ($package_dirs.Count -eq 0)
    {
        throw "Failed to find downloaded SymCrypt NuGet package in: `"${global:download_path}`""
    }

    # ------------------------ Package File Discovery ------------------------ #
    # select the package directory to use; print a warning if multiple are
    # found
    $package_dir = $package_dirs[0]
    if ($package_dirs.Count -gt 1)
    {
        $msg = "Found multiple SymCrypt NuGet packages in: `"${global:download_path}`":`n"
        foreach ($dir in $package_dirs)
        {
            $msg = "$msg - $($dir.FullName)`n"
        }
        $msg = "${msg}Selecting the first one found: `"$(package_dir.FullName)`""
        Write-Warning "$msg"
    }
    Write-Host "Selected SymCrypt NuGet package at: $($package_dir.FullName)"

    # search the package directory for the `nupkg` file
    $nupkg_files = Get-ChildItem -Path "$($package_dir.FullName)" -Filter "*.nupkg" -File
    if ($nupkg_files.Count -eq 0)
    {
        $msg = "Failed to find SymCrypt NuGet package file (`*.nupkg`) in downloaded NuGet package directory: `"$($package_dir.FullName)`""
        $msg = "$msg Please ensure that the package was downloaded correctly."
        throw "$msg"
    }

    # select the first-found `nupkg` file
    $nupkg_file = $nupkg_files[0]
    if ($nupkg_files.Count -gt 1)
    {
        $msg = "Found multiple SymCrypt NuGet package files (`*.nupkg`) in downloaded NuGet package directory: `"$($package_dir.FullName)`":`n"
        foreach ($file in $nupkg_files)
        {
            $msg = "$msg - $($file.FullName)`n"
        }
        $msg = "Selecting the first one found: `"$(nupkg_file.FullName)`""
        Write-Warning "$msg"
    }
    Write-Host "Selected SymCrypt NuGet package file at: $($nupkg_file.FullName)"

    # ----------------- Package File Expanion & Installation ----------------- #
    # rename the `nupkg` file to have a `.zip` extension (remove the existing
    # `.zip`, if one exists)
    $nupkg_zip_path = "$($nupkg_file.FullName).zip"
    Remove-Item -Path "$nupkg_zip_path" -ErrorAction SilentlyContinue -Force
    Rename-Item -Path "$($nupkg_file.FullName)" -NewName "$nupkg_zip_path" -Force
    Write-Host "Renamed NuGet package file to: ${nupkg_zip_path}"

    # extract the contents of the `nupkg` (zip) file into the package directory
    Expand-Archive -Path "${nupkg_zip_path}" -DestinationPath "$($package_dir.FullName)" -Force
    Write-Host "Extracted NuGet package contents to: $($package_dir.FullName)"

    # create the install path, if it doesn't already exist
    New-Item -Path "${global:install_path}" -ItemType "directory" -Force
    $global:install_path = get_full_path -Path "${global:install_path}"

    # copy the package contents into the install path
    Copy-Item -Path "$($package_dir.FullName)\*" -Destination "${global:install_path}" -Recurse -Force
    Write-Host "Copied SymCrypt NuGet package contents to: ${global:install_path}"

    return "$($package_dir.FullName)"
}

# Looks in the install path for the symcrypt DLL.
function get_dll_path
{
    # recursively search the install path for SymCrypt DLLs
    $dll_paths = Get-ChildItem -Path "${global:install_path}" -Filter "$global:symcrypt_dll_name" -File -Recurse
    if ($dll_paths.Count -eq 0)
    {
        throw "Failed to find SymCrypt DLL (`$global:symcrypt_dll_name`) in install path: `${global:install_path}`""
    }

    # iterate through the DLLs and make sure the path they are in matches the
    # architecture we're looking for
    $dll_arch_matches = @()
    $arch_regex = [Regex]"${global:symcrypt_arch}"
    foreach ($dll in $dll_paths)
    {
        # check if the directory path contains the architecture string
        $dll_path_lower = $dll.FullName.ToLower()
        if ($arch_regex.IsMatch($dll_path_lower))
        {
            $dll_arch_matches += @("$($dll.FullName)")
        }
    }

    # if we found *no* architecture matches, but we did find DLLs, warn the
    # user and select the first DLL
    if ($dll_arch_matches.Count -eq 0)
    {
        $msg = "Found SymCrypt DLLs in install path, but none matched the architecture `"${global:symcrypt_arch}`":`n"
        foreach ($dll in $dll_paths)
        {
            $msg = "$msg - $($dll.FullName)`n"
        }

        $dll_path = $dll_paths[0]
        $msg = "${msg}Selecting the first one found: `"$($dll_path.FullName)`""
        Write-Warning "$msg"

        return "$dll_path"
    }

    # if we found multiple matches, warn the user and select the first one
    if ($dll_arch_matches.Count -gt 1)
    {
        $msg = "Found multiple SymCrypt DLLs matching architecture `"${global:symcrypt_arch}`":`n"
        foreach ($match in $dll_arch_matches)
        {
            $msg = "$msg - $($match)`n"
        }
        $dll_path = $dll_arch_matches[0]
        $msg = "${msg}Selecting the first one found: `"$($dll_arch_matches[0])`""
        Write-Warning "$msg"

        return "$dll_path"
    }

    # at this point, we should have exactly one architecture-matching DLL
    Write-Host "Found SymCrypt DLL matching architecture `"${global:symcrypt_arch}`": `"$($dll_arch_matches[0])`"."
    return "$($dll_arch_matches[0])"
}

# Helper function that copies a file to a destination, only if the destination
# file does not already exist. Log messages and errors are used to indicate
# success or failure.
function maybe_copy_file
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )

    # make sure the source file exists
    if (-not (Test-Path -Path "$SourcePath" -PathType Leaf))
    {
        throw "Failed to find file: `"$SourcePath`""
    }

    # copy the file to the destination only if it doesn't already exist
    if (-not (Test-Path -Path "$DestinationPath" -PathType Leaf))
    {
        Copy-Item -Path "$SourcePath" -Destination "$DestinationPath" -Force
        Write-Host "Copied `"$SourcePath`" to `"$DestinationPath`"."
    }
}

function main
{
    Param
    (
        [Parameter(Mandatory=$false)]
        [string]$DownloadPath=$null,
        [Parameter(Mandatory=$false)]
        [string]$InstallPath=$null,
        [Parameter(Mandatory=$false)]
        [string]$InstallMethod=$null,
        [Parameter(Mandatory=$false)]
        [string]$SymcryptVersion=$null,
        [Parameter(Mandatory=$false)]
        [string]$SymcryptOS="windows",
        [Parameter(Mandatory=$false)]
        [string]$SymcryptArchitecture="amd64|x64|x86_64|x86-64"
    )

    # determine which installation method to use:
    #
    # 1. GitHub (download a release from the SymCrypt GitHub repo)
    # 2. NuGet Feed (download a release from the internal SymCrypt NuGet feed)
    if ($InstallMethod -eq $null -or $InstallMethod -eq "")
    {
        Write-Host "No installation method specified; defaulting to internal NuGet feed."
        $InstallMethod = "nuget"
    }
    else
    {
        $InstallMethod = $InstallMethod.ToLower().Trim()
        if ($InstallMethod -ne "github" -and $InstallMethod -ne "nuget")
        {
            $msg = "Invalid installation method specified: `"${InstallMethod}`"."
            $msg = "$msg Valid options are `"github`" and `"nuget`"."
            throw "$msg"
        }
    }
    Write-Host "Using installation method: `"${InstallMethod}`"."

    # if the NuGet method is selected, but we aren't running in an ADO
    # pipeline, warn the user that this may fail. This script depends on a
    # `NuGetAuthenticate` step in the ADO pipeline to set up authentication to
    # the internal feed.
    if ($InstallMethod -eq "nuget")
    {
        $is_ado_pipeline = is_running_in_ado_pipeline
        if (!$is_ado_pipeline)
        {
            $msg = "You are attempting to install SymCrypt via the internal NuGet feed outside of an Azure DevOps pipeline."
            $msg = "$msg This may fail if you do not have access to the feed from your current environment."
            $msg = "$msg If you encounter issues, consider using the `"github`" installation method instead."
            Write-Warning "$msg"
        }
    }

    # establish a default SymCrypt version, if one was not specified
    if ($SymcryptVersion -eq $null -or $SymcryptVersion -eq "")
    {
        # choose a different default based on the installation method
        if ($InstallMethod -eq "nuget")
        {
            $global:symcrypt_version = "$global:symcrypt_version_default_nuget"
        }
        else # GitHub install
        {
            $global:symcrypt_version = "$global:symcrypt_version_default_github"
        }

        # show a message indicating what version will be targeted by default
        $msg = "No SymCrypt version specified; defaulting to `"$global:symcrypt_version`""
        if ($global:symcrypt_version -eq $null -or $global:symcrypt_version -eq "")
        {
            $msg = "${msg} (latest)"
        }
        $msg = "${msg}."
        Write-Host "$msg"
    }
    else
    {
        $global:symcrypt_version = $SymcryptVersion.ToLower().Trim()
    }

    # establish defaults for the download and install path
    $global:download_path = $DownloadPath
    if (!$DownloadPath)
    {
        # by default, we'll download to the system temp path, which looks
        # something like this:
        #   C:\Users\USERNAME\AppData\Local\Temp
        $global:download_path = [System.IO.Path]::GetTempPath()
    }
    $global:install_path = $InstallPath
    if (!$InstallPath)
    {
        # by default, we'll extract the archive to the local app data path,
        # which looks something like this:
        #   C:\Users\USERNAME\AppData\Local
        $global:install_path = [System.Environment]::GetFolderPath("LocalApplicationData")
        $global:install_path = Join-Path -Path "${global:install_path}" -ChildPath "symcrypt"
    }
    Write-Host "Download Path: ${global:download_path}"
    Write-Host "Install Path: ${global:install_path}"

    # sanitize the symcrypt input strings
    $global:symcrypt_os = $SymcryptOS.ToLower().Trim()
    $global:symcrypt_arch = $SymcryptArchitecture.ToLower().Trim()

    # download the release, then extract
    #
    # PowerShell has some weird return value behavior; I'm using [-1] to get
    # around some issues. See this link for more info:
    # https://stackoverflow.com/questions/29556437/how-to-return-one-and-only-one-value-from-a-powershell-function
    $symcrypt_dir = $null
    if ($InstallMethod -eq "nuget")
    {
        $symcrypt_dir = (download_nuget_release)[-1]
    }
    else # GitHub install
    {
        $symcrypt_dir = (download_github_release)[-1]
    }

    # find the DLL within the install path
    $dll_path = get_dll_path
    $dll_dir = Split-Path "${dll_path}" -Parent

    # next, we'll make sure the DLL, LIB, and PDB files are present in a "dll"
    # subdirectory in the install path. This file structure is needed by
    # certain pipeline stages that consume SymCrypt
    $dll_subdir = Join-Path -Path "$global:install_path" -ChildPath "dll"
    New-Item -Path "$dll_subdir" -ItemType "directory" -Force

    # copy the DLL into the "dll" subdirectory, unless it already exists
    $dll_subdir_path = Join-Path -Path "$dll_subdir" -ChildPath "$global:symcrypt_dll_name"
    maybe_copy_file -SourcePath "$dll_path" -DestinationPath "$dll_subdir_path"

    # do the same thing for the LIB file. Start by looking for the LIB file in
    # the source directory
    $lib_name = [System.IO.Path]::ChangeExtension("$global:symcrypt_dll_name", ".lib")
    $lib_path = Join-Path -Path "$dll_dir" -ChildPath "$lib_name"
    $lib_subdir_path = Join-Path -Path "$dll_subdir" -ChildPath "$lib_name"
    maybe_copy_file -SourcePath "$lib_path" -DestinationPath "$lib_subdir_path"

    # do the same thing for the PDB file. Start by looking for the PDB file in
    # the source directory
    $pdb_name = [System.IO.Path]::ChangeExtension("$global:symcrypt_dll_name", ".pdb")
    $pdb_path = Join-Path -Path "$dll_dir" -ChildPath "$pdb_name"
    $pdb_subdir_path = Join-Path -Path "$dll_subdir" -ChildPath "$pdb_name"
    maybe_copy_file -SourcePath "$pdb_path" -DestinationPath "$pdb_subdir_path"

    # set the SYMCRYPT_LIB_PATH environment variable to point at the DLL's
    # parent directory. Set the environment variable to the user scope, such
    # that it persists beyond this shell process
    [System.Environment]::SetEnvironmentVariable("${global:symcrypt_lib_path_name}", "${dll_subdir}", [System.EnvironmentVariableTarget]::User)
    Write-Host "Set ${global:symcrypt_lib_path_name}=`"${dll_subdir}`"."

    # install the DLL to Windows\System32
    $dll_name = Split-Path "${dll_path}" -Leaf
    $dll_dest = "C:\Windows\System32\${dll_name}"
    Copy-Item -Path "${dll_path}" -Destination "${dll_dest}" -Force
    Write-Host "Copied SymCrypt DLL to: ${dll_dest}"

    return 0
}

$retcode = main @args
exit $retcode

