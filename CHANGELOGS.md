# Changelog  
All notable changes to this project will be documented in this file.  

## Version 1.0.0  
- single file source code ( both backdoor and listener )  
- direct shell access  
- get target system information  
- AES encrypted communication  
- add/remove firewall rules  
- backdoor access protection with password  
- run powershell commands and scripts  
- spawn independent powershell session  
- screenshot  
- dump clipboard  
- check for VM and sandbox  
- windows persistence using registry keys  
- download/upload files  
- client/server connection wait  
- dump windows hashes using ntds and reg save methods  

## Version 2.0.0  
### Changes  
- completely refactored code base and modular structure  
- improved sysinfo function  

### Added  
- threaded command and control script with session handling  
- execution of commands on multiple sessions  
- threaded keylogger  
- enable/disable RDP  
- enable/disable UAC  
- turn on/off display  

### Removed  
- backdoor password protection removed to prevent interfering with `cast` commands  

## Version 2.1.0  
### Changes  
- major changes in the configuration script  
- bug fixes in cnc session handling functionality  
- minor code refactor  

### Added  
- integrated pyinstaller 3.6 and pyarmor for automatic obfuscation and packing  

