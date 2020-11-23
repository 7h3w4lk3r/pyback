# PYBACK Version 2.0  
#### Another FUD (if you keep it that way) cross-platform backdoor and CNC written in python 2.  
#### i tried to make the code as clean as possible for future development and as i dont consider myself a developer i would be happy to have some feedback and suggestions on this project.  

# Top Features  
.  Cross-platform modules (of course)  
.  Direct shell access ( no need to type extra garbage )  
.  AES encrypted communication  
.  Command and Control center  
.  Can execute commands on all sessions at the same time (happy SKs?)  
.  Download/upload files  
.  Check for virtual machine and sandbox  
.  Take screenshots  
.  Dump clipboard  
.  Keylogger
.  Spawn a separate powershell session  
.  Enable/disable RDP  
.  Enable/disable UAC  
.  Easy session interaction and handling  
.  and there will be more :)  

# Installation  
### :warning: the backdoor should be compiled in a system with OS and architecture same as the target :warning:  

### requirements:  
#### python 2 version 2.7.15 or later  
#### VCforPython for windows targets, download from  <a href="https://www.microsoft.com/en-us/download/details.aspx?id=44266"> here </a>  
#### to install pyback simply run the setup.py  
#### pyback will detect your OS type and install the packages accordingly.  
`python setup.py`  

# Usage  
#### after running the setup script, you can either change the configurations manually in lib/setting.py or you can have the config.py script to do it for you.  
`python config.py`  

#### this script will take 3 parameters: ip/dns, port and password for AES encryption.  
#### after running the config script you can compile the backdoor however you want. i use pyinstaller.  
` pyinstaller --onefile --noconsole backdoor.py`  

#### send the backdoor, start the c2 and wait for connections.  
` python cnc.py`  

# Usage Tips  
.  DO NOT USE QUOTES in path names, for example use `file name` instead of `"file name"` when changing directories with `cd`  
.  If you want to upload a file it should be placed in the same directory as the cnc.py file.  
.  spawn module will spawn a separate shell using powershell for windows, catch it with netcat.  
.  While using the CNC shell your prompt will be like this: `[ CNC ] >>>` and it can run local system commands.  
.  To get a list of all available commands in CNC or backdoor prompt simply type `help`.  
.  ANY COMMAND not included in the help banners will be executed as system shell commands so be carefull with that.  

# To Do  
.  Add more post-exploitation modules  
.  Add a low-level port scanner  
.  you tell me...  

# POC  
### we all know that no tool like this will stay as FUD as it is, specially when it gets more attention (hopefully). so do me (and yourself) a favor and make it stay under the radar a little bit longer.  
:heavy_exclamation_mark: DO NOT upload this on VirusTotal or anywhere else, I DID IT FOR YOU :heavy_exclamation_mark:  

### using pyinstaller version 3.1.1:  

![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/image.png) 

# Contact  
Email: bl4ckr4z3r@gmail.com  
