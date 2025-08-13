# Building Catch2 Functional Tests
Build the tests from `<REPOROOT>/plugins/ossl/engine/tests` folder.

```bash
$ mkdir bld_engine_tests
$ cd bld_engine_tests
$ cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -B . -S ..
$ ninja
```
The executable `AZIHSMEngineTests` will be created in the `bld_engine_tests/tests` folder.
Change `Debug` or `Release` build as needed.

# Running Catch2 Functional Tests
Run the tests using the following command:
```bash
$ ./tests/AZIHSMEngineTests --reporter compact --success
```

## Linking tests to a specific OpenSSL version
By default, the tests will be linked to the system's default OpenSSL installation version. To link the tests to a different version of OpenSSL, specify the installation path with `-DOPENSSL_ROOT_DIR=<OpensslInstallDirecory>` to the cmake command.

For instance, to link to the `OpenSSL 3.3.1` installed in a custom path `/opt/openssl3.3.1`, use the following cmake command: 

`cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -DOPENSSL_ROOT_DIR=/opt/openssl-3.3.1 B . -S ..`
