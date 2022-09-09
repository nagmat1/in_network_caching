import sys
import time
import subprocess
from subprocess import run, PIPE
from multiprocessing import Process
import hashlib
from scapy.all import send, IP, ICMP, srp
import pcap
import dpkt
from scapy.all import *

resend = False
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096
port = 5201
port2 = 50505
s = socket.socket()
#socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(3))
perc30 = False


def handle_pkt(pkt):
    global resend
    global SEPARATOR
    try :
        setir = pkt[IP].load
    except :
        setir = ""
    #print("Load = ",setir)    
    if "RESEND" in str(setir):
        resend = True
        return


def send_file2(s,filename,port):
    global perc30
    iter2 = 0
    s.send(f"{filename}{SEPARATOR}{filesize}".encode())

    progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale = True, unit_divisor=1024)

    with open(filename, "rb") as f:
        while True :
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                s.sendall(f"<EOF>{SEPARATOR}".encode())
                #sys.stdout.flush()
                break
            s.sendall(bytes_read)
            progress.update(len(bytes_read))
            iter2 = iter2 + len(bytes_read)

           
print("---------------------- Starting The Sender Application -------------------------")
filename = sys.argv[2] #"twibot20.json"

host = sys.argv[1]  #"92.168.1.1"
print("Host = {} , Filename={} ".format(host,filename))
filesize = os.path.getsize(filename)
print(f"[+] Connecting to {host}:{port}")
s.bind(('192.168.1.2',0))
s.setsockopt(socket.SOL_SOCKET, 25, str("enp1s0f1" + '\0').encode('utf-8'))

s.connect((host,port))
print("[+] Connected.")
send_file2(s,filename,port)

#Calculate Md5 phase 
file_hash = hashlib.md5()
needed_hash = hashlib.md5(open(filename,'rb').read()).hexdigest()
print("Needed hash = ",needed_hash)
s.send(f"{needed_hash}{SEPARATOR}<HASH>".encode())
print("Send needed hash \n")

#if filesize <= 2000000000 :
#    print("Starting parsing process on the background \n")
#    cmd = 'sudo python3 /home/nnazarov/exper/converter/taze_ver_dpkt.py > /home/nnazarov/exper/converter/results.txt 2> errors.log &'
#    p = subprocess.Popen([cmd],shell=True)


print("Waiting RESEND signal...")
pkt = sniff(iface = 'enp2s0', filter='icmp', prn = lambda x : handle_pkt(x),count=1)

if resend :
    print("Resending the file from mirror server \n ")
s.close()
filename2 = '/home/nnazarov/exper/converter/'+filename
filesize2 = os.path.getsize(filename2)
old_f2 = 0
c2 = 0
while (filesize != filesize2) :
    print("Filesize = {} , filesize2 = {} ".format(filesize,filesize2))
    filesize2 = os.path.getsize(filename2)
    time.sleep(2)
    if old_f2 == filesize2 :
        c2 = c2 + 1

    old_f2 = filesize2
    if (c2 >= 2) and (filesize2/filesize > 0.95) :
        break

print("Final Filesize = {} , filesize2 = {} ".format(filesize,filesize2))
print("Starting Sender from Mirror server \n")
s2 = socket.socket()
host = sys.argv[1]  #"92.168.1.1"
print("Host = {} , Filename={} ".format(host,filename2))
filesize = os.path.getsize(filename2)
print(f"[+] Connecting to {host}:{port2}")
s2.bind(('192.168.1.3',0))
s2.setsockopt(socket.SOL_SOCKET, 25, str("enp2s0" + '\0').encode('utf-8'))
s2.connect((host,port2))
print("[+] Connected.")
send_file2(s2,filename2,port2)
