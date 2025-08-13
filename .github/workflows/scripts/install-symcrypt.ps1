$url = "https://github.com/microsoft/SymCrypt/releases/download/v103.5.1/symcrypt-windows-amd64-release-103.5.1-907622c.zip"
$tempDirectory = [System.IO.Path]::GetTempPath()
$outputFile = Join-Path -Path $tempDirectory -ChildPath "archive.zip"
Invoke-WebRequest -Uri $url -OutFile $outputFile
$userLocalAppData = [System.Environment]::GetFolderPath("LocalApplicationData")
$extractTo = Join-Path -Path $userLocalAppData -ChildPath "symcrypt"
if (!(Test-Path -Path $extractTo)) {
    New-Item -ItemType Directory -Path $extractTo
}
Expand-Archive -Path $outputFile -DestinationPath $extractTo
Remove-Item -Path $outputFile -Force
$libpath = Join-Path -Path $extractTo -ChildPath "dll"
$setxCommand = "SETX SYMCRYPT_LIB_PATH `"$libpath`""
Invoke-Expression $setxCommand
$sourceFile = Join-Path -Path $libpath -ChildPath "symcrypt.dll"
$destinationDir = "C:\Windows\System32"
if (Test-Path -Path $sourceFile) {
    Copy-Item -Path $sourceFile -Destination $destinationDir -Force
} else {
    Write-Error "Source file not found: $sourceFile"
}
