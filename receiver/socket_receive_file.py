import socket
import tqdm
import os
import hashlib
import time
import subprocess
import scapy
from scapy.all import send, IP, ICMP


SERVER_HOST = "192.168.1.1"
SERVER_PORT = 5201
port2 = 50505
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"
needed_hash = ""
found_hash  = ""

def receive(client_socket):
    global needed_hash
    global found_hash
    received = client_socket.recv(BUFFER_SIZE).decode()
    filename,filesize = received.split(SEPARATOR)
    print("Filename = {} , Filesize = {} ".format(filename,filesize))
    filename = os.path.basename(filename)
    filesize = int(filesize)
    finished = False
    #progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    t = time.time()
    with open('/data/'+filename,"wb") as f:
        while True:
            bytes_read = client_socket.recv(BUFFER_SIZE)
            if not bytes_read:
                break
            #progress.update(len(bytes_read))
            if SEPARATOR in str(bytes_read) :
                if "EOF" in str(bytes_read):
                    #print("SEPARATOR IS ",str(bytes_read))
                    f.write(bytes_read[:-16])
                    finished = True
                if "HASH" in str(bytes_read):
                    received = bytes_read.decode()
                    needed_hash = received[:32]
                    print("Needed hash = ",needed_hash)
                    break
            elif not(finished):
                f.write(bytes_read)
    print("Total transfer time = ",time.time()-t)

    print("Calculating md5 value of the received file ... ")
    file_hash = hashlib.md5()
    timeStarted = time.time()
    found_hash = hashlib.md5(open('/data/'+filename,'rb').read()).hexdigest()
    print("Found hash = ", found_hash)
    timeDelta = time.time() - timeStarted                     # Get execution time.
    print("Finished checking md5sum process in "+str(timeDelta)+" seconds.")

print("------------------ Starting the Application -----------------------")
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((SERVER_HOST, SERVER_PORT))
s.listen(35)

print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")

client_socket, address = s.accept()

receive(client_socket)
s.close()

if needed_hash == found_hash :
    print("Successfully received file ")
else :
    print("RESEND SIGNAL ")
    send(IP(dst="192.168.1.3",src="192.168.1.1") / ICMP() / b"RESEND")
    send(IP(dst="192.168.1.2",src="192.168.1.1") / ICMP() / b"RESEND")

    time.sleep(2)
    s2 = socket.socket()
    s2.bind((SERVER_HOST, port2 ))
    s2.listen(35)
    print(f"[*] Listening as {SERVER_HOST}:{port2}")
    client_socket2, address = s2.accept()
    receive(client_socket2)
