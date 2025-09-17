#!/bin/bash

# Writes a message to STDERR.
function __log()
{
    printf "%s\n" "$*" >&2
}

# Polls the GitHub API to find the appropriate URL to download symcrypt from.
function __get_github_url()
{
    # process any command-line arguments
    repo_version="latest"
    if [ $# -ge 1 ]; then
        repo_version="$1"
    fi

    repo_owner="microsoft"
    repo_name="symcrypt"
    url="https://api.github.com/repos/${repo_owner}/${repo_name}/releases"

    # curl the URL, and pass the output into a JSON parser that extracts the
    # browser download URL from each of the releases' assets
    __log "Polling GitHub API for SymCrypt releases..."
    download_urls=$(curl "${url}" | \
                    jq -M -r ".[].assets" | \
                    jq -M -r ".[].browser_download_url")
    
    # if the curl failed, the array is likely empty
    if [ ${#download_urls} -eq 0 ]; then
        msg="Failed to poll GitHub API at: \"${url}\"."
        msg="${msg} Please make sure the URL is correct."
        __log "${msg}"
        return 1
    fi
    
    # set parameters to filer the download URLs
    target_architecture="amd64"
    target_os="linux"
    target_keyword="generic"

    # filter the download URLs, and sort them by version, from latest to oldest
    download_urls=($(echo "${download_urls[@]}" | \
                     grep "${target_architecture}" | \
                     grep "${target_os}" | \
                     grep "${target_keyword}" | \
                     uniq | \
                     sort --version-sort --reverse))
    
    # iterate through the download URLs to find the correct one
    for download_url in ${download_urls[@]}; do
        # if we're looking for the latest version, return the first entry in
        # the list
        if [[ "${repo_version}" == *"latest"* ]]; then
            echo "${download_url}"
            return 0
        fi

        # otherwise, compare the version with the URL, and return it if matches
        if [[ "${download_url}" == *"${repo_version}"* ]]; then
            echo "${download_url}"
            return 0
        fi
    done
    
    __log "Could not find a matching SymCrypt download URL for version \"${repo_version}\"."
    return 2
}

# Takes in a GitHub URL to a `.tar.gz` file and downloads, unpacks, and
# installs SymCrypt from it.
function __install_from_github_url()
{
    if [ $# -lt 1 ]; then
        __log "Error: at least one argument (the GitHub download URL) must be provided."
        return 1
    fi

    __log "Downloaded SymCrypt release from URL: \"${symcrypt_url}\"..."
    wget -N "${symcrypt_url}"

    # make sure the download succeeded
    symcrypt_fname="$(basename "${symcrypt_url}")"
    symcrypt_fpath="./${symcrypt_fname}"
    if [ ! -f "./${symcrypt_fname}" ]; then
        __log "Failed to download SymCrypt from GitHub."
        return 1
    fi

    # unpack the tarfile
    tar -xzf "${symcrypt_fpath}"

    # copy everything from the include directory to `/usr/include/`
    include_src="./inc"
    include_dst="/usr/include"
    if [ ! -d "${include_src}" ]; then
        __log "Failed to find SymCrypt include directory at: ${include_src}."
        return 2
    fi
    sudo cp ${include_src}/* "${include_dst}/"
    __log "Installed SymCrypt include files to ${include_dst}/."

    # copy all files in `lib` to `/usr/lib/` (use `cp -P` to ensure the
    # symbolic links are preserved when copied to `/usr/lib`)
    lib_src="./lib"
    lib_dst="/usr/lib"
    if [ ! -d "${lib_src}" ]; then
        __log "Failed to find SymCrypt lib directory at: ${lib_src}."
        return 2
    fi
    sudo cp -P ${lib_src}/*libsymcrypt* "${lib_dst}/"
    __log "Installed SymCrypt lib files to ${lib_dst}/."
}

# Main function for installing on Ubuntu.
function __main_ubuntu()
{
    if [ $# -lt 1 ]; then
        __log "Error: at least one argument (the Ubuntu version) must be provided. (Ex: \"20.04\")"
        return 1
    fi
    
    url="https://packages.microsoft.com/config/ubuntu/$1/packages-microsoft-prod.deb"
    download_path="/tmp/packages-microsoft-prod.deb"
    
    # download the package; if downloading failed, return early and show an error
    wget "${url}" -O "${download_path}"
    wget_result=$?
    if [ ${wget_result} -ne 0 ]; then
        __log "Error: failed to download Ubuntu SymCrypt package from this URL: \"${url}\"."
        return 2
    fi

    # install downloaded `.deb` via `dpkg`
    sudo dpkg -i "${download_path}"
    rm "${download_path}"

    # update and install symcrypt
    sudo apt-get update
    sudo apt-get install -y symcrypt

    return 0
}

# Main function for installing on Mariner.
function __main_mariner()
{
    # if an argument was provided, interpret it as the symcrypt version
    symcrypt_version="latest"
    if [ $# -ge 1 ]; then
        symcrypt_version="$1"
    fi
    
    # get the proper GitHub URL from which we should download the SymCrypt
    # shared library
    symcrypt_url="$(__get_github_url "${symcrypt_version}")"
    result=$?
    if [ ${result} -ne 0 ]; then
        return ${result}
    fi

    # make a temporary directory to house the downloaded tarfile
    tmpdir="$(pwd)/.symcrypt_download"
    rm -rf "${tmpdir}"
    mkdir "${tmpdir}"
    pushd "${tmpdir}" > /dev/null

    # next, download and install symcrypt from the GitHub URL
    __install_from_github_url "${symcrypt_url}"
    result=$?
    
    popd > /dev/null

    # delete the temporary directory
    rm -rf "${tmpdir}"

    return ${result}
}

# Shows a help menu for the script.
function __show_help()
{
    echo "Available Command-Line Arguments:"
    echo "---------------------------------"
    echo "  -h          Shows this help menu."
    echo "  -d DISTRO   Sets the Linux distribution this script should install for."
    echo "              Supported distributions:"
    echo "                  -d ubuntu"
    echo "                  -d mariner"
    echo "              (Defaults to Ubuntu)"
    echo "---------------------------------"
    echo "Ubuntu installations require an additional parameter: the Ubuntu version."
    echo "To install SymCrypt on Ubuntu, follow these examples:"
    echo "  ./install-symcrypt.sh -d ubuntu 20.04"
    echo "  ./install-symcrypt.sh 22.04"
    echo ""
    echo "Mariner installations will default to the latest SymCrypt release."
    echo "However, the version can be specified as an optional parameter. For example:"
    echo "  ./install-symcrypt.sh -d mariner 103.5.1"
}

# Main function.
function __main()
{
    distro="ubuntu"

    # process command-line arguments
    while getopts "hd:" arg; do
        case ${arg} in
            h)
                __show_help
                return 0
                ;;
            d)
                distro="${OPTARG,,}"
                __log "User-specified Linux distribution: \"${distro}\"."

                # make sure the provided distro matches a supported distro
                if [[ "${distro}" != *"ubuntu"* ]] &&
                   [[ "${distro}" != *"mariner"* ]]; then
                    __show_help
                    return 99
                fi
                ;;
            *)
                __show_help
                return 0
        esac
    done

    # shift all remaining arguments down, so we can pass them to the helper
    # functions
    shift $((OPTIND-1))

    # if we're on mariner, run the mariner function
    if [[ "${distro}" == *"mariner"* ]]; then
        __log "Linux distribution is Mariner. Installing SymCrypt..."
        __main_mariner "$@"
        result=$?
        return ${result}
    # if we're on ubuntu, run the ubuntu function
    elif [[ "${distro}" == *"ubuntu"* ]]; then
        __log "Linux distribution is Ubuntu. Installing SymCrypt..."
        __main_ubuntu "$@"
        result=$?
        return ${result}
    fi

    return 0
}

__main "$@"
result=$?
exit ${result}

