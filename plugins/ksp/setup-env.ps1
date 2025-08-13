# This script is used to set up a PowerShell environment for debugging and/or
# fuzzing the KSP on Windows.

# Globals
$script_dir = "$PSScriptRoot"

# The container/windows image the Maritchoras pipeline uses can be found here:
# 
# https://eng.ms/docs/products/onebranch/infrastructureandimages/containerimages/windowsimages/windows2019vse2022
#
# It describes in its latest release notes that VS version 17.11.2 is used. So,
# we want to download the equivalent version for our installers. See this link
# for URLs to access all versions:
# 
# https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-history
$vs_installer_url_enterprise = "https://download.visualstudio.microsoft.com/download/pr/f73d49f7-22b6-4a11-b980-72f3daae77a6/f1e8155c31a7b747fd9f01efaf012e75a4e37c428e74a322674e923c6ae71a3a/vs_Enterprise.exe"
$vs_installer_url_buildtools = "https://download.visualstudio.microsoft.com/download/pr/f73d49f7-22b6-4a11-b980-72f3daae77a6/e258e16d0e663bcd43db4979704b913bec3d19c052d09ea3013803a6913f28ab/vs_BuildTools.exe"


# ================================= Helpers ================================== #
# Helper function for logging messages to output.
function log()
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [string]$Prefix="",
        [Parameter(Mandatory=$false)]
        [string]$IndentLevel=0
    )
    
    # build a message string
    $msg = ""
    if ($Prefix.Length -gt 0)
    { $msg = "[$Prefix] " }

    # add indentations
    $indent = 0
    while ($indent -lt $IndentLevel)
    {
        $msg = "$msg    "
        $indent++
    }

    # add the message
    $msg = "$msg$Message"

    # print it!
    Write-Host "$msg"
}

# Helper function for the various path-adding functions below.
function path_add_helper([string] $varname, [string] $value)
{
    $path = [System.Environment]::GetEnvironmentVariable("$varname")

    # if the current path doesn't contain the given string, append it
    if ($path -notlike "*$value*")
    {
        $path = "$path;$value"
        [System.Environment]::SetEnvironmentVariable("$varname", "$path")
        log -Prefix "path-add" -Message "`"$value`" has been added to ```$$varname``."
        return $true
    }
    else
    {
        log -Prefix "path-add" -Message "`"$value`" is already in ```$$varname``."
        return $false
    }
}

# Helper function that adds to the system $PATH environment variable if the
# given string is not already present.
function path_add([string] $value)
{
    return path_add_helper "PATH" "$value"
}

# Helper function that adds a given path to the `_NT_SOURCE_PATH` env var if it
# hasn't already been added.
function nt_source_path_add([string] $value)
{
    return path_add_helper "_NT_SOURCE_PATH" "$value"
}

# Helper function that adds a given path to the `_NT_SOURCE_PATH` env var if it
# hasn't already been added.
function nt_symbol_path_add([string] $value)
{
    return path_add_helper "_NT_SYMBOL_PATH" "$value"
}

# Function used to download files from a given URL.
function download_file()
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [string]$RetryCount=10
    )

    # if the file already exists, delete it
    if (Test-Path -Path "$Path")
    {
        Remove-Item -Force -Path "$Path"
    }

    # we'll attempt the download several times before giving up
    $attempt = 0
    while ($true)
    {
        try
        {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $client = New-Object System.Net.WebClient
            $client.Headers.Add("user-agent", "curl")
            $client.DownloadFile($url, $path)
            break
        }
        catch [System.Exception]
        {
            # if we've already reached the max retry count, throw the exception
            if ($attempt -ge $RetryCount)
            {
                log -IndentLevel 1 -Message "Maximum retry count reached. Throwing exception..."
                throw
            }
            else
            {
                log -IndentLevel 1 -Message "Download failed. Retrying..."
                $attempt++
                Start-Sleep 5
            }
        }
    }
}


# ================================= Fuzzing ================================== #
# Downloads the VS installer from online and uses it to install VS and other
# needed fuzzing dependencies.
# 
# This was created to assist with getting the necessary dependencies installed
# when running the Windows KSP fuzzing tests in a pipeline. See these links for
# more information:
#
# https://learn.microsoft.com/en-us/visualstudio/install/use-command-line-parameters-to-install-visual-studio
# https://learn.microsoft.com/en-us/visualstudio/install/workload-component-id-vs-build-tools
function install_vs
{
    param
    (
        [switch]$UseVSEnterprise=$false,
        [switch]$UseVSBuildTools=$false,
        [Parameter(Mandatory=$false)]
        [string]$InstallPath="",
        [Parameter(Mandatory=$false)]
        [string[]]$Add=@()
    )

    # make sure exactly one of the VS executables was selected
    if (($UseVSEnterprise -and $UseVSBuildTools) -or (!$UseVSEnterprise -and !$UseVSBuildTools))
    {
        Write-Error "Please specify exactly one option: ``-UseVSEnterprise`` or ``-UseVSBuildTools``."
        return $false
    }

    $pfx = "vs-install"

    # choose a file name and remote URL depending on the choice of installer
    $vsi_url = $null
    $vsi = "$script_dir"
    if ($UseVSEnterprise)
    {
        $vsi_url = "$vs_installer_url_enterprise"
        $vsi = "$vsi\vs_enterprise.exe"
    }
    elseif ($UseVSBuildTools)
    {
        $vsi_url = "$vs_installer_url_buildtools"
        $vsi = "$vsi\vs_buildtools.exe"
    }

    # download the installer
    log -Prefix "$pfx" -Message "Downloading VS Installer..."
    download_file -URL "$vsi_url" -Path "$vsi"
    if (!(Test-Path -Path "$vsi"))
    {
        log -Prefix "$pfx" -IndentLevel 1 -Message "Failed to download VS Installer."
        return $false
    }
    log -Prefix "$pfx" -IndentLevel 1 -Message "Successfully downloaded to: $vsi"
    
    # construct a list of arguments to pass to the installer. See here for a
    # list of options:
    # 
    # https://learn.microsoft.com/en-us/visualstudio/install/use-command-line-parameters-to-install-visual-studio
    $args = ""
    $args = "${args}--quiet"        # don't display the GUI (use `--passive` when debugging locally)
    $args = "$args --wait"          # wait for the installation to finish
    $args = "$args --norestart"     # don't restart the machine
    $args = "$args --nocache"       # don't use any cached files (and don't cache any downloaded files)
    $args = "$args --includeRecommended" # includes recommended components for anything we install
    $args = "$args --includeOptional" # includes optional components for anything we install

    # iterate through the list of dependencies and add them all to the
    # invocation arguments
    foreach ($dependency in $Add)
    { $args = "$args --add $dependency" }

    # add the install path, if one was specified
    if ($InstallPath -ne "")
    {
        $args = "$args --installPath `"$InstallPath`""
        log -Prefix "$pfx" -IndentLevel 1 -Message "Set install path to: `"$InstallPath`"."
    }
    
    # fire up the installer
    log -Prefix "$pfx" -Message "Invoking VS Installer with arguments: ``$args``"
    $proc = Start-Process -FilePath "$vsi" `
                          -Wait `
                          -PassThru `
                          -NoNewWindow `
                          -ArgumentList "$args"

    # delete the executable
    Remove-Item -Path "$vsi"
    
    # check the exit code and return/log accordingly
    if ($proc.ExitCode -ne 0)
    {
        # it seems that the installer won't always return a zero exit code,
        # even on a success. See this SO post:
        #
        # https://stackoverflow.com/questions/55697044
        #
        # So, this may not be a failure. We'll just print out the return code
        # and *not* flag it as a failure.
        $ec = $proc.ExitCode
        log -Prefix "$pfx" -IndentLevel 1 -Message "VS Installer executable exited with code: $ec."
    }

    log -Prefix "$pfx" -IndentLevel 1 -Message "Installation complete."
    return $true
}

# Searches the filesystem for a VS installation. The path to the most recent VS
# installation is returned. (If VS 2022 is installed, this path will be
# returned over VS 2019 or other earlier versions that might be installed.)
#
# If no installation was found, null is returned.
function find_vs
{
    param
    (
        [switch]$UseVSEnterprise=$false,
        [switch]$UseVSBuildTools=$false
    )
    
    # make sure exactly one of the VS executables was selected
    if (($UseVSEnterprise -and $UseVSBuildTools) -or (!$UseVSEnterprise -and !$UseVSBuildTools))
    {
        Write-Error "Please specify exactly one option: ``-UseVSEnterprise`` or ``-UseVSBuildTools``."
        return $false
    }

    # define and search for a few specific root directories at which the VS
    # installation should be living
    $vs_roots = @()
    if ($UseVSEnterprise)
    {
        $vs_roots += "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
        $vs_roots += "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise"
    }
    elseif ($UseVSBuildTools)
    {
        $vs_roots += "C:\Program Files\Microsoft Visual Studio\2022\BuildTools"
        $vs_roots += "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
    }
    $vs_root = $null
    foreach ($path in $vs_roots)
    {
        if (Test-Path -Path "$path")
        {
            # if a root path has already been found, and we're finding *other*
            # installations, then these multiple installations may create
            # trouble later. (This script will choose one of these root
            # directories to find the AddressSanitizer DLL within, and it will
            # be put on the `$env:PATH`. It's possible this script's logic
            # could choose the wrong one; cargo may decide to invoke the MSVC
            # compiler in a different installation. Long story short, let's
            # warn the user.)
            if ($vs_root -ne $null)
            {
                $msg = ""
                $msg = "$msg We've already selected a VS installation to use:"
                $msg = "$msg `"$vs_root`"."
                $msg = "$msg However, we found another installation: `"$path`"."
                $msg = "$msg There appear to be multiple installations of VS."
                $msg = "$msg This may create trouble later."
                Write-Warning "$msg"
                continue
            }
            
            $vs_root = "$path"
        }
    }

    return $vs_root
}

# Searches the given root directory for a MSVC directory and returns it.
function find_msvc([string] $vs_root)
{
    $msvc_path = "$vs_root\VC\Tools\MSVC"
    if (!(Test-Path "$msvc_path "))
    { return $null }

    # get all sub-directories, which should correspond to different MSVC
    # versions. If NONE are found, we've got trouble; return NULL
    $msvc_versions = Get-ChildItem -Path "$msvc_path" -Directory
    if ($msvc_versions.Count -eq 0)
    { return $null }

    # otherwise, if we have *multiple* versions, this could also create trouble
    # later: what if we select the wrong version to add to the `$env:PATH`
    # here, and cargo decides to use a different version when building the
    # fuzzing targets? We'll warn the user
    $msvc_versions = $msvc_versions | Sort-Object -Property Name -Descending | % { $_.FullName }
    if ($msvc_versions.Count -gt 1)
    {
        $msg = "Found several versions of MSVC installed at `"$msvc_path`": `n"
        foreach ($path in $msvc_versions)
        {
            $msg = "$msg - `"$path`"`n"
        }
        Write-Warning "$msg"
    }

    # return ALL MSVC versions; it'll be up to the caller which one to use
    return $msvc_versions
}

# Searches the MSVC installation directory for the bin directory.
function find_msvc_bin([string] $msvc_root)
{
    # search multiple locations
    $bins = @(
        "$msvc_root\bin\Hostx64\x64"
        "$msvc_root\bin\Hostx86\x64"
    )
    foreach ($path in $bins)
    {
        if (Test-Path "$path")
        { return "$path" }
    }

    return $null
}

# Searches the given directory for the address sanitizer DLL. Returns the path,
# or null.
function find_asan([string] $root)
{
    # should look like: "clang_rt.asan_dynamic-x86_64"
    $asan_paths = Get-ChildItem -Path "$root" -Recurse -Filter "*clang_rt*asan_dynamic*64*.dll" 
    if ($asan_paths.Count -eq 0)
    { return $null }
    return $asan_paths[0]
}

# Sets up the environment for fuzzing the KSP.
function setup_env_fuzzing
{
    $pfx = "fuzz-setup"

    # cargo-fuzz requires Rust nightly features, so we must specify
    # `RUSTC_BOOTSTRAP=1` because MSRustUp does not have a nightly version.
    $rustc_bootstrap_env = "RUSTC_BOOTSTRAP"
    [System.Environment]::SetEnvironmentVariable("$rustc_bootstrap_env", "1")
    log -Prefix "$pfx" -Message "Set ``$rustc_bootstrap_env=1`` to gain access to Rust nightly features."
    
    # --------------------- VS Installation and Location --------------------- #
    $install_vs_args = @{ InstallPath = "" }

    # attempt to locate a pre-existing visual studio installation
    $vs_path = find_vs -UseVSEnterprise
    $msvc_paths = $null
    if ($vs_path -ne $null)
    {
        $install_vs_args["InstallPath"] = "$vs_path"
        log -Prefix "$pfx" -Message "Found existing VS installation at `"$vs_path`"."

        # see if we can also find an existing MSVC installation
        $msvc_paths = find_msvc($vs_path)
    }

    # the C++ AddressSanitizer is necessary for fuzzing
    $install_vs_args["Add"] = @("Microsoft.VisualStudio.Component.VC.ASAN")
    
    # if we can't find MSVC already, we'll install the latest version
    if ($msvc_paths -eq $null)
    { $install_vs_args["Add"] += "Microsoft.VisualStudio.Component.VC.Tools.x86.x64" }

    # install visual studio
    $success = install_vs -UseVSEnterprise @install_vs_args
    if (!$success)
    {
        return $false
    }
    
    # Visual Studio must be installed now; make sure it can be found (don't do
    # this if we already located it above)
    if ($vs_path -eq $null)
    {
        $vs_path = find_vs -UseVSEnterprise
        if ($vs_path -eq $null)
        {
            $msg = "Could not find a VS installation."
            $msg = "$msg Please make sure it is installed on this machine."
            Write-Error "$msg"
            return $false
        }
        log -Prefix "$pfx" -Message "Found VS installation at `"$vs_path`"."
    }
    
    # ---------------------------- MSVC Location ----------------------------- #
    # search for MSVC, if we didn't already find it above
    if ($msvc_paths -eq $null)
    {
        $msvc_paths = find_msvc($vs_path)
        if ($msvc_paths -eq $null)
        {
            $msg = "Could not find MSVC within the VS installation."
            $msg = "$msg Please make sure you have installed MSVC with the VS Installer."
            Write-Error "$msg"
            return $false
        }
    }

    # walk through each MSVC path and look for the bin directory
    $msvc_bin = $null
    foreach ($msvc_path in $msvc_paths)
    {
        # find the MSVC's bin directory
        $bin = find_msvc_bin($msvc_path)
        if ($bin -eq $null)
        {
            $msg = "Could not find MSVC bin directory within `"$msvc_path`"."
            Write-Warning "$msg"
            continue
        }

        # if we haven't already found a bin, set it
        if ($msvc_bin -eq $null)
        {
            $msvc_bin = $bin
            log -Prefix "$pfx" -Message "Found MSVC bin directory: `"$msvc_bin`"."
        }
        # if we HAVE already found a bin, then it seems we have found multiples
        # MSVC installations with their own bin directories. Let's warn the
        # user, since this script may select the wrong one
        else
        {
            $msg = "Found ANOTHER MSVC bin directory here: `"$bin`"."
            $msg = "$msg This script has selected this directory to use: `"$msvc_bin`"."
            $msg = "$msg The presence of multiple MSVC installations may create issues later."
            Write-Warning "$msg"
        }
    }
    if ($msvc_bin -eq $null)
    {
        $msg = "Failed to find a MSVC bin directory."
        $msg = "$msg Please make sure the MSVC build tools are properly installed."
        Write-Error "$msg"
        return $false
    }
    
    # ----------------- C++ AddressSanitizer (ASAN) Location ----------------- #
    # find the address sanitizer within the MSVC bin directory
    $asan_path = find_asan($msvc_bin)
    if ($asan_path -eq $null)
    {
        $msg = "Could not find AddressSanitizer DLL directory within `"$msvc_bin`"."
        $msg = "$msg Please make sure you have installed the AddressSanitizer with the VS Installer."
        Write-Error "$msg"
        return $false
    }
    $asan_path = $asan_path.FullName
    log -Prefix "$pfx" -Message "Found MSVC AddressSanitizer at `"$asan_path`"."
    
    # add the path to the address sanitizer to the PATH
    $asan_dir_path = Split-Path -Path "$asan_path" -Parent
    $success = path_add "$asan_dir_path"

    return $true
}


# ================================ Debugging ================================= #
# Sets up Windows debugging symbols.
function setup_env_debug_symbols
{
    log -Prefix "debug" -Message "Setting up Windows debugging symbols..."

    # create directories
    $sym_path = "C:\Symbols"
    if (!(Test-Path -Path "$sym_path"))
    { mkdir "$sym_path" }
    if (!(Test-Path -Path "$sym_path\Src"))
    { mkdir "$sym_path\Src" }
    if (!(Test-Path -Path "$sym_path\Sym"))
    { mkdir "$sym_path\Sym" }
    if (!(Test-Path -Path "$sym_path\SymCache"))
    { mkdir "$sym_path\SymCache" }

    # set up the 'tier 2' symbol cache marker files
    echo Index2 > C:\Symbols\Sym\index2.txt
    echo PingMe > C:\Symbols\Sym\pingme.txt

    # compress the folder tree
    compact.exe /C /I /Q /S:"C:\Symbols"
    
    # set up symbols
    setx DBGHELP_HOMEDIR C:\Symbols
    $success = nt_source_path_add("SRV*C:\Symbols\Src")
    $success = nt_symbol_path_add("SRV*C:\Symbols\Sym*https://symweb.azurefd.netsetx")
    setx _NT_SYMCACHE_PATH C:\Symbols\SymCache

    return $true
}

# Sets up AZIHSM KSP debugging symbols.
function setup_env_debug_symbols_azihsmksp
{
    log -Prefix "debug" -Message "Setting up Azure Integrated HSM KSP debugging symbols..."

    # grab the target/debug directory path; this is where the KSP's DLL PDB
    # file will be outputted after building
    $build_path = "$script_dir\target\debug"
    $success = nt_symbol_path_add("$build_path")
}

# Sets up the environment with useful debugging tools.
function setup_env_debug
{
    # look for the Windows Debugger installation
    $debug_path = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
    log -Prefix "debug" -Message "Ensuring Windows debugging binaries are on the system path..."
    if (!(Test-Path -Path "$debug_path"))
    {
        $msg = "Could not find the Windows Debugging tool path."
        $msg = "$msg Please consider installing them."
        Write-Warning "$msg"
    }
    else
    { $success = path_add "$debug_path" }

    # set up debugging symbols
    setup_env_debug_symbols
    setup_env_debug_symbols_azihsmksp
    
    return $true
}

function main
{
    # set up parameters
    param
    (
        [Parameter(Position=0)]
        [string] $mode
    )

    # if no mode was provided, show a brief help message
    if (-not $mode)
    {
        log -Message "This script will set up your PowerShell environment for developing the KSP."
        log -Message "Please provide one of the following arguments:"
        log -Message " "
        log -Message "    fuzz        (to set up your shell for fuzzing)"
        log -Message "    debug       (to set up your shell for debugging)"
        log -Message "    all         (to do all of the above)"
        log -Message " "
        return 0
    }
    
    # determine if the "all" option was chosen
    $do_all = $false
    if ($mode -like "*all*")
    { $do_all = $true }

    log -Message "Mode: $mode"
    
    # set up for fuzzing, if applicable
    if ($do_all -or $mode.Equals("fuzz"))
    {
        $success = setup_env_fuzzing
        if (!$success)
        { return 1 }
    }

    # set up for debugging, if applicable
    if ($do_all -or $mode.Equals("debug"))
    {
        $success = setup_env_debug
        if (!$success)
        { return 2 }
    }

    log -Message "Done!"
    return 0
}

# run the main function and set the exit code
$retcode = main @args
exit $retcode

