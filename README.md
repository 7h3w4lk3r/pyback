# PYBACK  
another FUD (if you keep it that way) cross-platform python backdoor. im working on it as a hobby and would like to have some feedback and suggestions.  

# Features    
.  Direct shell access  
.  AES encrypted channel   
.  Add/remove firewall rules  
.  Backdoor access protection with password  
.  Run powershell commands and scripts  
.  Spawn an independent powershell session to a remote machine    
.  Screenshot  
.  Check for sandbox and VM   
.  Download/upload files  
.  Dump clipboard  
.  Persistance using REGKEY  
.  Client or server connection wait  
.  Dump hashes with ntds and reg save methods ( files should be downloaded manually ) 

# Change Log  
. Removed the enum functions and refactored code  
. Backdoor login protection added  

# Usage Tips  
. DO NOT use single or double quotes in file name or directory path for any target, for example:  
to change the directory to `\'test file'`, type in `cd test file` NOT `cd 'test file'`  
. All commands NOT LISTED in help will be executed as target system shell commands.  
. To use upload functionality you should put the target file in the same directory as the listener.py file.   
. Spawn function will run an FUD reverse powershell payload on victim machine, you can catch it with `nc -nvlp [port]`  

# Usage  
### . remember to change ip and port in both files.(no-ip dns is available)
### . change the backdoor access password in the backdoor.py file  

## for linux targets:  
`pip install -r linux_requirments.txt`  

## for windows targets:   
:warning: WARNING: DO NOT USE WINE FOR WINDOWS TARGET COMPILATION :warning:  
:warning: use python 2.7.15 32bit version only :warning:   
install VCforPython from <a href="https://www.microsoft.com/en-us/download/details.aspx?id=44266"> here </a>.  
`pip install -r windows_requirments.txt`  
`pyinstaller -onefile -noconsole backdoor.py`   
 
### pyinstaller will encrease the detection rate.   

### for a list of commnads type 'help' in the listener console when connected to the backdoor.   

# To Do  
. Add a low-level port scanner  
. Add more credential dumping and persistence methods  
. Add obfuscation methods  

# PoC  
:heavy_exclamation_mark: DO NOT upload this on VirusTotal or anywhere else, I DID IT FOR YOU :heavy_exclamation_mark:  
  
  using pure python code:  
   
![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/poc.png)  
  
  using pyinstaller version 3.1.1:  

![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/image.png) 

  
# Contact  
Email: bl4ckr4z3r@gmail.com  


