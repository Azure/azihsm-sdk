<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Running GitHub Actions workflows locally on Linux

Some of the jobs in the workflows located in [.github/workflows](../../.github/workflows/) can be executed locally by utilizing the [act](https://nektosact.com/) tool. Below are steps for installing and configuring the tool on Linux for our repository:

1. Install `act` via the bash script at <https://nektosact.com/installation/index.html#bash-script>.
   - **Note**: This script will install the tool to `./bin` relative to the current working directory. To install to a system binaries directory you will generally need `sudo` (for example `sudo ./install.sh -b /usr/local/bin`), or install to `~/.local/bin` and ensure it is in your `PATH`.
1. Install Docker Engine (see the official install docs for your distro; Ubuntu guide: <https://docs.docker.com/engine/install/ubuntu/>).
1. **Optional**: Run the `create_new_cache_ubuntu` job from the root of the repository to save a new local cache:

   ```bash
   act -j create_new_cache_ubuntu -P ubuntu-24.04=catthehacker/ubuntu:rust-24.04
   ```

1. **Optional**: Make note of the full Git commit SHA in the key the cache is saved under. This value will be used as the `CACHE_KEY_ID` environment variable in any jobs you want to run with access to the cache:

   ```text
   [Create New Cache/create_new_cache_ubuntu] ⭐ Run Main Save Cargo cache
   [Create New Cache/create_new_cache_ubuntu]   🐳  docker cp src=/home/<user>/.cache/act/actions-cache-save@v5/ dst=/var/run/act/actions/actions-cache-save@v5/
   [Create New Cache/create_new_cache_ubuntu]   🐳  docker exec cmd=[/opt/acttoolcache/node/24.18.0/x64/bin/node /var/run/act/actions/actions-cache-save@v5/dist/save-only/index.js] user= workdir=
   | [command]/usr/bin/tar --posix -cf cache.tzst --exclude cache.tzst -P -C /path/to/repo --files-from manifest.txt --use-compress-program zstdmt
   | Cache Size: ~133 MB (139948729 B)
   | Cache saved successfully
   | Cache saved with key: Linux-cargo-f51f9f9970662de0207d19a02c4315f689be500b
   [Create New Cache/create_new_cache_ubuntu]   ✅  Success - Main Save Cargo cache [3.430124244s]
   ```

   In this output, `f51f9f9970662de0207d19a02c4315f689be500b` is the full Git commit SHA.

1. Use `--env`, `-j/--job` and `-P/--platform` flags to run a known good job with the catthehacker/ubuntu:rust-24.04 image:

   ```bash
   # run test_ubuntu_smoke job w/o local cache (will result in cache miss)
   act -j test_ubuntu_smoke -P ubuntu-24.04=catthehacker/ubuntu:rust-24.04

   # run test_ubuntu_smoke job w/ local cache (requires steps 3 & 4 to be run prior)
   act --env CACHE_KEY_ID=f51f9f9970662de0207d19a02c4315f689be500b -j test_ubuntu_smoke -P ubuntu-24.04=catthehacker/ubuntu:rust-24.04
   ```

The following jobs are known good jobs that have been verified to work with the `act` tool:

- Create New Cache (`.github/workflows/create_new_cache.yml`): `create_new_cache_ubuntu`
- Firmware Uno (`.github/workflows/fw_uno.yml`): `build_ubuntu`
- Rust (`.github/workflows/rust.yml`): `test_ubuntu_smoke`

All other jobs have not yet been verified and will likely require additional setup and/or configuration.
