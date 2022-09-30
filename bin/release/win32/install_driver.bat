cd /d %~dp0

rem Installing the network hooking driver build for 32-bit systems

rem Copy the driver to system folder
copy netfilter2.sys %windir%\system32\drivers

rem Register the driver
nfregdrv.exe netfilter2

pause