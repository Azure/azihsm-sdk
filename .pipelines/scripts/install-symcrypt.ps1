# Copyright (C) Microsoft Corporation. All rights reserved.
# This script installs SymCrypt to a specified location.

# SymCrypt configuration (the null fields are set below in the main function).
$global:symcrypt_lib_path_name = "SYMCRYPT_LIB_PATH"
$global:symcrypt_repo_owner = "microsoft"
$global:symcrypt_repo_name = "SymCrypt"
$global:symcrypt_version = $null
$global:symcrypt_os = $null
$global:symcrypt_arch = $null
$global:download_path = $null
$global:download_retry_count = 4
$global:install_path = $null

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
function get_release_url
{
    $url = "https://api.github.com/repos"
    $url = "${url}/${global:symcrypt_repo_owner}"
    $url = "${url}/${global:symcrypt_repo_name}"
    $url = "${url}/releases"

    # if we're retrieving the latest version, just append "latest"
    if ($global:symcrypt_version -eq "latest")
    { $url = "${url}/latest" }
    # otherwise, use the version as a tag and add "tags/" to the URL
    else
    { $url = "${url}/tags/${global:symcrypt_version}" }

    return "$url"
}

# Downloads the SymCrypt release from GitHub and extracts it to the install
# location.
function download_release
{
    $url = get_release_url

    # --------------------------- Archive Download --------------------------- #
    Write-Host "Pinging Release URL: ${url}"
    $response = Invoke-RestMethod `
                -Uri "${url}" `
                -Headers @{"User-Agent" = "PowerShell"}

    # iterate through the assets and look for one that matches our OS and
    # architecture
    $chosen_asset = $null
    foreach ($asset in $response.assets)
    {
        $name = $asset.name.ToLower().Trim()
        if (("${name}" -Match "${global:symcrypt_os}") -and
            ("${name}" -Match "${global:symcrypt_arch}"))
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

# Looks in the install path for the symcrypt DLL.
function get_dll_path
{
    # build a path to the location where the DLL should be stored
    $dll_path = "${global:install_path}"
    $dll_path = Join-Path -Path "${dll_path}" -ChildPath "dll"
    $dll_path = Join-Path -Path "${dll_path}" -ChildPath "symcrypt.dll"

    # if the file doesn't exist, complain
    if (!(Test-Path "${dll_path}" -PathType Leaf))
    {
        throw "Failed to find SymCrypt DLL at the expected location: ${dll_path}"
    }

    Write-Host "Found DLL at: ${dll_path}"
    return "${dll_path}"
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
        [string]$SymcryptVersion="v103.5.1",
        [Parameter(Mandatory=$false)]
        [string]$SymcryptOS="windows",
        [Parameter(Mandatory=$false)]
        [string]$SymcryptArchitecture="amd64"
    )
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
    $global:symcrypt_version = $SymcryptVersion.ToLower().Trim()
    $global:symcrypt_os = $SymcryptOS.ToLower().Trim()
    $global:symcrypt_arch = $SymcryptArchitecture.ToLower().Trim()

    # download the release, then extract
    #
    # PowerShell has some weird return value behavior; I'm using [-1] to get
    # around some issues. See this link for more info:
    # https://stackoverflow.com/questions/29556437/how-to-return-one-and-only-one-value-from-a-powershell-function
    $symcrypt_dir = (download_release)[-1]

    # find the DLL, then set the SYMCRYPT_LIB_PATH environment variable to
    # point at it's parent directory. Set the environment variable to the user
    # scope, such that it persists beyond this shell process
    $dll_path = get_dll_path
    $dll_dir = Split-Path "${dll_path}" -Parent
    [System.Environment]::SetEnvironmentVariable("${global:symcrypt_lib_path_name}", "${dll_dir}", [System.EnvironmentVariableTarget]::User)
    Write-Host "Set ${global:symcrypt_lib_path_name}=`"${dll_dir}`"."

    # install the DLL to Windows\System32
    $dll_name = Split-Path "${dll_path}" -Leaf
    $dll_dest = "C:\Windows\System32\${dll_name}"
    Copy-Item -Path "${dll_path}" -Destination "${dll_dest}" -Force
    Write-Host "Copied SymCrypt DLL to: ${dll_dest}"

    return 0
}

$retcode = main @args
exit $retcode

