## Building and Running the tests

### Building the tests
To build the AZIHSM-KSP tests, run the following command from tests directory:

    cargo test --release --no-run

### Running the tests
#### Running Individual Test Binaries
Each test binary is generated in .exe format and is available in the target directory. To execute an individual test, simply run the corresponding .exe file directly.

    .\Example_test.exe

#### Running All Tests at Once
To run all the test binaries simultaneously, you can use the following command. This will iterate over all .exe files matching the pattern test_*.exe and execute each test sequentially.

    Forfiles /m test_*.exe /c "cmd /c @file --test-threads=1"