# Writing Samples

Part of standing AziHSM up and readying it for production use by 1P and 3P customers is creating small sample programs that demonstrate AziHSM's capabilities, and show customers how to use it.
These samples should be written with uniform design, uniform style, readable code, comments to explain details, and without any memory leaks or other bugs.
This document describes best practices to follow when writing a Windows C++ sample for the AziHSM KSP.

## Use "AziHSM" instead of "Manticore"

"Manticore" is the internal name for this project.
Make sure to refer to Manticore as "AziHSM", which is short for "**A**zure **i**ntegrated **HSM**".
(The "zi" should be lowercase; every other letter should be uppercase.)

## Use Proper Data Types for Return Codes

Windows has several different data types that are used across various APIs to return status codes.
In general, write your sample to preserve the data type returned by the Windows API you're invoking for as long as possible up the call stack.
Except for the `main` function, do not use a standard `int` data type to return status codes; instead, use the following data types in these scenarios:

* Return the [`NTSTATUS`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/87fba13e-bf06-450e-83b1-9241dc81e781) data type if your function invokes the [BCrypt API](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt) and does not invoke *any other* Windows APIs.
    * Return [`STATUS_SUCCESS`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55) to indicate a successful `NTSTATUS` value.
* Return the `SECURITY_STATUS` data type if your function invokes the [NCrypt API](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt) and does not invoke *any other* Windows APIs.
    * These values are a subset of `HRESULT` (see the next bullet point), so you may safely cast them to `HRESULT`.
* Return the [`HRESULT`](https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values) data type if your function invokes a mix of Windows API funtions, or implements its own logic without calling Windows APIs.
    * Use the [`HRESULT_FROM_NT()`](https://learn.microsoft.com/en-us/windows/win32/api/winerror/nf-winerror-hresult_from_nt) macro to convert a `NTSTATUS` data type to a `HRESULT`.
    * Return [`S_OK`](https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values) to indicate a sucessful `HRESULT` value.
    * Return [`E_FAIL`](https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values) to indicate a generic failure `HRESULT` value.
    * Use the [`SUCCEEDED()`](https://learn.microsoft.com/en-us/windows/win32/api/winerror/nf-winerror-succeeded) macro to determine if a `HRESULT` value indicates success.
    * Use the [`FAILED()`](https://learn.microsoft.com/en-us/windows/win32/api/winerror/nf-winerror-failed) macro to determine if a `HRESULT` value indicates failure.

When implementing your own logic, look for a fitting `HRESULT` value to return from [this page](https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values) or from `winerror.h`.
When returning an unknown or generic error code that doesn't match any existing status code, default to using `-1`.

## Organize Code into Helper Functions

Create one or more helper functions to abstract-away complex logic from the `main` function.
For complex demos, the `main` function should show the high-level flow of logic by calling helper functions that implement the details of invoking the NCrypt API (and other libraries).

<details>
<summary>(Click here for an example)</summary>

```cpp
SECURITY_STATUS open_provider(/* ... */)
{
    // NCryptOpenStorageProvider()
}

SECURITY_STATUS create_aes_key(/* ... */)
{
    // NCryptCreatePersistedKey()
    // NCryptSetProperty()
    // NCryptFinalizeKey()
}

NTSTATUS random_buffer(/* ... */)
{
    // BCryptOpenAlgorithmProvider
    // BCryptGenRandom
    // BCryptCloseAlgorithmProvider
}

SECURITY_STATUS encrypt_aes(/* ... */)
{
    // NCryptEncrypt()
}

HRESULT buffer_to_hex_str(/* ... */)
{
    // (logic to produce a hexadecimal string representation of the provided buffer)
}

int main(/* ... */)
{
    HRESULT status = S_OK;

    // 1. Open the storage provider.
    status = (HRESULT) open_provider(/* ... */);
    if (FAILED(status))
    {
        goto cleanup;
    }

    // 2. Create an AES key.
    status = (HRESULT) create_aes_key(/* ... */);
    if (FAILED(status))
    {
        goto cleanup;
    }

    // 3. Generate random plaintext to encrypt.
    status = HRESULT_FROM_NT(random_buffer(/* ... */));
    if (FAILED(status))
    {
        goto cleanup;
    }

    // 4. Encrypt the plaintext.
    status = (HRESULT) encrypt_aes(/* ... */);
    if (FAILED(status))
    {
        goto cleanup;
    }

    // 5. Create and print a hexadecimal string representing the ciphertext.
    status = buffer_to_hex_str(/* ... */);
    if (FAILED(status))
    {
        goto cleanup;
    }
    printf(/* ... */);

cleanup:
    // (perform cleanup)
}
```

</details>

## Use the *Goto Cleanup* Design

Most samples will require the handling of several resources that need to be freed to prevent memory leaks.
Error codes must also be propagated out of the function call stack to ensure the program exits with a status code that accurately portrays the result of execution.
To achieve these goals, structure the `main` function and all helper functions with the `goto cleanup` design.

* All functions should have a `cleanup` label at the very end of the function.
* Every branch inside the function should eventually end up in the `cleanup` label (for both success and error scenarios).
    * Meaning, the *only* exit point in the fuction should be through the `cleanup` label.
* Resources should be freed within the `cleanup` label.
    * However, in success scenarios, you may *not* want to free some pointers that are being returned to the caller.
      This depends on your implementation.

<details>
<summary>(Click here for an example)</summary>

```cpp
HRESULT helper_1(void** result)
{
    // Initialize a function-wide "status" field, for tracking error codes
    HRESULT status = S_OK;

    // (do logic to allocate memory...)
    void* data = NULL;
    status = allocate_some_memory(&data);
    if (FAILED(status))
    {
        // If allocation failed, goto cleanup
        goto cleanup;
    }

    // ... other logic ... (will `goto cleanup` on failure)

    // On success, update `result` to point at the data we allocated above. Set
    // `data` to NULL after doing so, to "move" the data's ownership to
    // `*result`.
    *result = data;
    data = NULL;

cleanup:
    // Retrieve the latest value of `status`, and save it as the exit code
    HRESULT exit_status = status;

    // Does `data` still point to an allocated buffer? If so, something went
    // wrong above, and we should free its memory before returning.
    if (data != NULL)
    {
        free(resource1);
    }

    // Exit with the status we saved above
    return exit_status;
}

HRESULT helper_2(void** result)
{
    // ... (same idea as `helper_1()`)
}

HRESULT helper_3(void** result)
{
    // ... (same idea as `helper_1()`)
}

HRESULT helper_4(void* data1, void* data2, void* data3)
{
    // (do some sort of processing with the three data pointers...)
}

int main()
{
    // Initialize a function-wide "status" field, for tracking error codes
    HRESULT status = S_OK;

    // Initialize all resource pointers before any `goto` statements.
    void* resource1 = NULL;
    void* resource2 = NULL;
    void* resource3 = NULL;

    // Call the first helper function; get a pointer to a heap-allocated
    // resource.
    status = helper_1(&resource1);
    if (FAILED(status))
    {
        goto cleanup;
    }

    // Call the second helper function; get a pointer to another heap-allocated
    // resource.
    status = helper_2(&resource2);
    if (FAILED(status)) 
    {
        goto cleanup;
    }

    // Call the third helper function; get a pointer to ANOTHER heap-allocated
    // resource.
    status = helper_3(&resource3);
    if (FAILED(status)) 
    {
        goto cleanup;
    }

    // Finally, now that we have all of our resources allocated, call the
    // fourth helper function to do some sort of processing with them
    status = helper_4(resource1, resource2, resource3);
    if (FAILED(status))
    {
        goto cleanup;
    }

cleanup:
    // Retrieve the latest value of `status`, and save it as the exit code.
    HRESULT exit_status = status;

    // For each resource, check to see if it was initialized. If it was, we
    // need to free it.
    
    // Free the first resource, if it was allocated.
    if (resource1 != NULL)
    {
        free(resource1);
    }

    // Free the second resource, if it was allocated.
    if (resource2 != NULL)
    {
        free(resource2);
    }

    // Free the third resource, if it was allocated.
    if (resource3 != NULL)
    {
        free(resource3);
    }

    // Exit with the status we saved above
    return (int) exit_status;
}
```

</details>

## Set Return Pointers at the Last Possible Moment

In functions that pass return values through pointers provided by the caller, wait until the last possible moment to update those caller-provided return pointers.
These should be set just before returning, when you know the function has succeeded and you'll be returning a successful status code.

<details>
<summary>(Click here for an example)</summary>

```cpp
HRESULT helper_func(BYTE** result, size_t* result_len)
{
    BYTE* buffer = NULL;
    size_t buffer_len = 0;

    // (logic that creates a buffer and fills it up with bytes)

    // (check for errors; if an error occurs, use `goto cleanup` method to
    // free the buffer)
    
    // (at this point, we know the function has succeeded; set return pointers
    // and null-out local buffer pointer)
    *result = buffer;
    *result_len = buffer_len;
    buffer = NULL;

helper_func_cleanup:
    // (cleanup and return)
}
```

</details>

## Create a README for each Sample

Make sure to create a `README.md` file to go with your sample.
It should describe:

* What scenario the sample demonstrates.
* How to build & run the sample

Be sure to also write your markdown such that it matches the styling seein in the [microsoft/Windows-classic-samples](https://github.com/microsoft/Windows-classic-samples) GitHub repository.
See [this file](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Security/CipherEncryptionDecryption/README.md) for an example.

## Comment the Code

Write comments in the sample's code to explain processes, function calls, variables, or anything else important that the reader may not find obvious.

## Add a Copyright to all Source Files

Because these samples will be open to the public, every source code file should have the following copyright at the top:

```cpp
// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
```
This is the same copyright message seen in the [OpenEnclave repository](https://github.com/openenclave/openenclave), and other Microsoft repositories that use the MIT license.

## Configure VS Projects to Build with Static Runtime Libraries

To reduce the DLLs the resulting executables are dependent on, configure your VS project to build the runtime library *statically*.
This will create an executable that does not require the Visual Studio runtime library to be installed on the system it is running on.
(Make sure to configure this for both the **Debug** and **Release** build configs.)
See [this page](https://learn.microsoft.com/en-us/cpp/build/reference/md-mt-ld-use-run-time-library) for more information.

<details>
<summary>(Click here to see an example of how to modify the `.vcxproj` file)</summary>

```diff
diff --git a/plugins/ksp/samples/ATTEST-UNWRAP-KEY/ATTEST-UNWRAP-KEY/ATTEST-UNWRAP-KEY.vcxproj b/plugins/ksp/samples/ATTEST-UNWRAP-KEY/ATTESTdiff --git a/plugins/ksp/samples/ATTEST-UNWRAP-KEY/ATTEST-UNWRAP-KEY/ATTEST-UNWRAP-KEY.vcxproj b/plugins/ksp/samples/ATTEST-UNWRAP-KEY/ATTEST-UNWRAP-KEY/ATTEST-UNWRAP-KEY.vcxproj
index bdf9c506..d7773402 100644
--- a/plugins/ksp/samples/ATTEST-UNWRAP-KEY/ATTEST-UNWRAP-KEY/ATTEST-UNWRAP-KEY.vcxproj
+++ b/plugins/ksp/samples/ATTEST-UNWRAP-KEY/ATTEST-UNWRAP-KEY/ATTEST-UNWRAP-KEY.vcxproj
@@ -57,6 +57,7 @@
       <PreprocessorDefinitions>_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <ConformanceMode>true</ConformanceMode>
       <AdditionalIncludeDirectories>%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
+      <RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>
     </ClCompile>
     <Link>
       <SubSystem>Console</SubSystem>
@@ -73,6 +74,7 @@
       <PreprocessorDefinitions>NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <ConformanceMode>true</ConformanceMode>
       <AdditionalIncludeDirectories>%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
+      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
     </ClCompile>
     <Link>
       <SubSystem>Console</SubSystem>
```

</details>

## Remove any 32-bit Build Settings from Project Files

AziHSM is only supported on 64-bit systems; be sure to remove any 32-bit build settings from your sample's Visual Studio project.
VS seems to add these in by default when creating a new project, so you'll have to remove them through the VS GUI, or by (carefully) modifying the `.sln` and `.vcxproj` files.

<details>
<summary>(Click here to see an example of how to modify the `.sln` file)</summary>

```diff
diff --git a/plugins/ksp/samples/ECDH-KBKDF-AESCBC/ECDH-KBKDF-AESCBC.sln b/plugins/ksp/samples/ECDH-KBKDF-AESCBC/ECDH-KBKDF-AESCBC.sln
index b212daa3..4643c777 100644
--- a/plugins/ksp/samples/ECDH-KBKDF-AESCBC/ECDH-KBKDF-AESCBC.sln
+++ b/plugins/ksp/samples/ECDH-KBKDF-AESCBC/ECDH-KBKDF-AESCBC.sln
@@ -8,19 +8,13 @@ EndProject
 Global
        GlobalSection(SolutionConfigurationPlatforms) = preSolution
                Debug|x64 = Debug|x64
-               Debug|x86 = Debug|x86
                Release|x64 = Release|x64
-               Release|x86 = Release|x86
        EndGlobalSection
        GlobalSection(ProjectConfigurationPlatforms) = postSolution
                {174CE219-E989-48C3-AD49-50D0F32FE48C}.Debug|x64.ActiveCfg = Debug|x64
                {174CE219-E989-48C3-AD49-50D0F32FE48C}.Debug|x64.Build.0 = Debug|x64
-               {174CE219-E989-48C3-AD49-50D0F32FE48C}.Debug|x86.ActiveCfg = Debug|Win32
-               {174CE219-E989-48C3-AD49-50D0F32FE48C}.Debug|x86.Build.0 = Debug|Win32
                {174CE219-E989-48C3-AD49-50D0F32FE48C}.Release|x64.ActiveCfg = Release|x64
                {174CE219-E989-48C3-AD49-50D0F32FE48C}.Release|x64.Build.0 = Release|x64
-               {174CE219-E989-48C3-AD49-50D0F32FE48C}.Release|x86.ActiveCfg = Release|Win32
-               {174CE219-E989-48C3-AD49-50D0F32FE48C}.Release|x86.Build.0 = Release|Win32
        EndGlobalSection
        GlobalSection(SolutionProperties) = preSolution
                HideSolutionNode = FALSE
```

</details>

<details>
<summary>(Click here to see an example of how to modify the `.vcxproj` file)</summary>

```diff
diff --git a/plugins/ksp/samples/ECDH-KBKDF-AESCBC/ECDH-KBKDF-AESCBC/ECDH-KBKDF-AESCBC.vcxproj b/plugins/ksp/samples/ECDH-KBKDF-AESCBC/ECDH-KBKDF-AESCBC/ECDH-KBKDF-AESCBC.vcxproj
index 49b9468d..517b9af2 100644
--- a/plugins/ksp/samples/ECDH-KBKDF-AESCBC/ECDH-KBKDF-AESCBC/ECDH-KBKDF-AESCBC.vcxproj
+++ b/plugins/ksp/samples/ECDH-KBKDF-AESCBC/ECDH-KBKDF-AESCBC/ECDH-KBKDF-AESCBC.vcxproj
@@ -1,14 +1,6 @@
 <?xml version="1.0" encoding="utf-8"?>
 <Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
   <ItemGroup Label="ProjectConfigurations">
-    <ProjectConfiguration Include="Debug|Win32">
-      <Configuration>Debug</Configuration>
-      <Platform>Win32</Platform>
-    </ProjectConfiguration>
-    <ProjectConfiguration Include="Release|Win32">
-      <Configuration>Release</Configuration>
-      <Platform>Win32</Platform>
-    </ProjectConfiguration>
     <ProjectConfiguration Include="Debug|x64">
       <Configuration>Debug</Configuration>
       <Platform>x64</Platform>
@@ -26,19 +18,6 @@
     <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
   </PropertyGroup>
   <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
-  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'" Label="Configuration">
-    <ConfigurationType>Application</ConfigurationType>
-    <UseDebugLibraries>true</UseDebugLibraries>
-    <PlatformToolset>v143</PlatformToolset>
-    <CharacterSet>Unicode</CharacterSet>
-  </PropertyGroup>
-  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'" Label="Configuration">
-    <ConfigurationType>Application</ConfigurationType>
-    <UseDebugLibraries>false</UseDebugLibraries>
-    <PlatformToolset>v143</PlatformToolset>
-    <WholeProgramOptimization>true</WholeProgramOptimization>
-    <CharacterSet>Unicode</CharacterSet>
-  </PropertyGroup>
   <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'" Label="Configuration">
     <ConfigurationType>Application</ConfigurationType>
     <UseDebugLibraries>true</UseDebugLibraries>
@@ -57,12 +36,6 @@
   </ImportGroup>
   <ImportGroup Label="Shared">
   </ImportGroup>
-  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
-    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
-  </ImportGroup>
-  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
-    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
-  </ImportGroup>
   <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
     <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
   </ImportGroup>
@@ -73,32 +46,6 @@
   <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
     <IncludePath>$(VC_IncludePath);$(WindowsSDK_IncludePath);$(ProjectDir)\..\..\include</IncludePath>
   </PropertyGroup>
-  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
-    <ClCompile>
-      <WarningLevel>Level3</WarningLevel>
-      <SDLCheck>true</SDLCheck>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
-      <ConformanceMode>true</ConformanceMode>
-    </ClCompile>
-    <Link>
-      <SubSystem>Console</SubSystem>
-      <GenerateDebugInformation>true</GenerateDebugInformation>
-    </Link>
-  </ItemDefinitionGroup>
-  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
-    <ClCompile>
-      <WarningLevel>Level3</WarningLevel>
-      <FunctionLevelLinking>true</FunctionLevelLinking>
-      <IntrinsicFunctions>true</IntrinsicFunctions>
-      <SDLCheck>true</SDLCheck>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
-      <ConformanceMode>true</ConformanceMode>
-    </ClCompile>
-    <Link>
-      <SubSystem>Console</SubSystem>
-      <GenerateDebugInformation>true</GenerateDebugInformation>
-    </Link>
-  </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
     <ClCompile>
       <WarningLevel>Level3</WarningLevel>
@@ -131,4 +78,4 @@
   <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
   <ImportGroup Label="ExtensionTargets">
   </ImportGroup>
</Project>
```

</details>

