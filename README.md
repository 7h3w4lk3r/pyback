# PYBACK
FUD cross-platform python2 backdoor  

# Features  
1-  Linux and windows post-exploitation enumeration  
2-  Run powershell commands and scripts  
3-  Spawn an independent powershell session to a remote machine (catch with netcat)  
4-  Screenshot  
5-  Check sandbox and VM (VM check only for windows, using wmi module)  
6-  Download/upload files  
7-  Dump clipboard  
8-  Run a fork bomb on victim machine, just for fun :)  
9-  Persistance using REGKEY (windows only)  
10- Client or server connection wait (one time only, no reconnecting yet)  
11- Dump hashes with ntds and reg save methods ( files should be manually downloaded ) 

# Usage
`pip install -r requirments.txt`  

to compile for windows install wmi with `pip install wmi`

tkinter most be installed by default, otherwise install it with:  
`apt install python-tk`  

pyinstaller will encrease the detection rate. use this version only:   
`pip install pyinstaller==3.1.1`  
`wine /root/.wine/drive_c/Python27/Scripts/pyinstaller.exe --onfile --noconsole  backdoor.py`  

change the port and ip or DNS in both listener.py and backdoor.py files.  

attacker side:  
`./listener.py`

victim side:  
`./backdoor.py`  


for a list of commnads type 'help' in the listener console when connected to the backdoor.   

# Tips

. to use upload functionality you should put the target file in the same directory as the listener.py file.  
. install rlwrap with `apt install rlwrap` and use `rlwrap ./listener.py` to have up and down arrow key for command cycling.  
. backdoor doesnt auto-activate the persistence module for better evation chance, if you want to change that simply uncomment the self.persistance() line in backdoor file.  
. the `enum` command results will be saved in the listener directory. to see colored output use `cat enum*.txt`  
. spawn function will run an FUD reverse powershell payload on victim machine, you can catch it with `rlwrap nc -nvlp [port]`  

# PoC  
  using pure python code:  
   
![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/poc.png)  
  
  using pyinstaller version 3.1.1:  

![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/image.png) 

  
# Contact  
Email: bl4ckr4z3r@gmail.com  
Telegram ID: @w4lk3r1998

