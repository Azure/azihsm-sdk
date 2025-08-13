# Tracing and Logging

## Log generation

`plugins/ksp` uses crate [log](https://docs.rs/log/latest/log/).

`plugins/ksp` also setup a tracing subscriber to collect logs generated from `mcr_api`.  
The log level to collect can be controlled by environment variable `AZIHSMKSP_LOG_LEVEL`. If this env variable is not set or empty, log level defaults to "INFO".  
The env variable can be one of the following values: "TRACE", "DEBUG", "INFO", "WARN", "ERROR".

```powershell
# Example: set log level to DEBUG
$env:AZIHSMKSP_LOG_LEVEL="DEBUG"
```

## Log viewing

Logs from KSP layer are provided to [Event Tracing for Windows](https://docs.rs/win_etw_macros/latest/win_etw_macros/), and can be viewed using [TraceView](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/traceview)

> TraceView is installed with [Windows Driver Kit](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)  
> TraceView is located in the tools\<Platform> subdirectory of the Windows Driver Kit (WDK), where <Platform> represents the platform you are running the trace session on, for example, x86, x64, or arm64. 

### View logs using TraceView

1. Open TraceView
2. Click on "File" -> "New Log Session"
3. Select Method "Manually Entered Control GUID or Hashed Name"
4. Enter GUID for AZIHSM KSP `6f3b7e7a-7f98-4fb5-a0ce-e994136df3e2`
    1. You can find it here: `plugins/ksp/src/etw_logger.rs`
5. Leave value as default for other options
6. As you make calls to KSP DLL, you will see logs in TraceView

### Capture logs using tracelog

1. Get tracelog.exe by following the instructions [here](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/tracelog)
2. Copy the `start_trace.bat`, `stop_trace.bat` and `guid.ctl` files from the `scripts` folder to the test machine.
3. Run `start_trace.bat`, reproduce the scenario, then run `stop_trace.bat`
