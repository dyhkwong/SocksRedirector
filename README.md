# SocksRedirector

Modified `SocksRedirector` demo from [Netfilter SDK](https://netfiltersdk.com/).
It transparently redirects TCP/UDP traffic to a specified SOCKS5 proxy (`wfp2socks`).
WFP level kernel driver is used to filter the transmitted packets.

## Usage
See `SocksRedirector.exe --help`.

Run `install_driver.bat` for installing and registering the network hooking driver. 
The driver starts immediately and reboot is not required.
Run `uninstall_driver.bat` to remove the driver from system.
Elevated administrative rights must be activated explicitly for registering the driver (run the scripts using "Run as administrator" context menu item in Windows Explorer). 

## License
All copyrights to NetFilter SDK are exclusively owned by the author - Vitaly Sidorov.

## Note
The pre-built demo driver provided by [Netfilter SDK](https://netfiltersdk.com/) filters no more than 1000000 TCP connections and UDP sockets.
After exceeding this limit the filtering continues again after system reboot.
You may [ordering](http://www.netfiltersdk.com/buy_now.html) a license for full version or source code.
