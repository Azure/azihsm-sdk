tracelog -stop KSPTrace
netsh trace convert ksp.etl overwrite=yes
start notepad.exe "ksp.txt"