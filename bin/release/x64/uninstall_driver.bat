cd /d %~dp0

rem Uninstall the network hooking driver

rem Try to unload the driver
sc stop netfilter2

rem Unregister the driver
nfregdrv.exe -u netfilter2

rem Delete driver file
del %windir%\system32\drivers\netfilter2.sys

pause