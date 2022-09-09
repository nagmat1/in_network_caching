#!/usr/local/bin/python2.7
import tempfile
import dpkt
import pcap
from dpkt.utils import mac_to_str, inet_to_str
import time
import hashlib
import subprocess
import sys

pcap_file='/home/nnazarov/exper/converter/dtn4.pcap'
started = False
SEPARATOR = "<SEPARATOR>"
cur_seq = 0
counter = 0
restarted = False
file_hash = hashlib.md5()
finished = False


def handle_pkt(packet):
    global started
    global file_hash
    global f3
    global counter
    global finished
    global SEPARATOR

    if SEPARATOR in str(packet) and not started :
        started = True
        setir2 = packet.decode()
        filename,filesize = setir2.split(SEPARATOR)
        file_hash = hashlib.md5()
        f3 = open('/home/nnazarov/exper/converter/'+filename,'wb')
        print("Filename = {} , filesize = {} ".format(filename,filesize))
        started = True
        return
    if started and SEPARATOR in str(packet):
        f3.write(packet[:-16])
        file_hash.update(packet[:-16])
        f3.close()
        print("The program is terminating \nCounter = {} ".format(counter))
        print("Final Hash = {},".format(file_hash.hexdigest()))
        finished = True
        exit()
        sys.stdout.flush()
    if started and packet != "" and not(finished) :
        file_hash.update(packet)
        f3.write(packet)
    sys.stdout.flush()


print("Starting ")

with open(pcap_file,'rb') as f :
    pcap = dpkt.pcap.Reader(f)
    for _, buf in pcap:
        counter = counter + 1
        #print(buf)
        eth = dpkt.ethernet.Ethernet(buf)
        #print(eth)
        if not isinstance(eth.data,dpkt.ip.IP):
            #print("NOT IP Packet")
            continue

        ip = eth.data
        #print(inet_to_str(ip.src)) 
        if isinstance(ip.data, dpkt.tcp.TCP):
            if inet_to_str(ip.src)!='192.168.1.2' :
                continue
            tcp = ip.data
            #counter = counter + 1
            seq_num = tcp.seq
            if not(restarted) and seq_num < 100000 :
                cur_seq = 0
                restarted = True
            if restarted and seq_num > 100000000 :
                restarted = False

            payload = bytes(ip.data)
            #print("counter = {}, seq_num = {}, Len = {}, cur_seq = {} , payload = {} ".format(counter,seq_num,ip.len,cur_seq,payload))
            #if seq_num > cur_seq and 
            if payload[32:] != b'' and seq_num >=cur_seq :
                if cur_seq == 0 :
                    cur_seq = tcp.seq
                else :
                    cur_seq = seq_num + ip.len - 52
                handle_pkt(payload[32:])
            #else : 
            #    print("Dropped counter = {}, seq_num = {}, Len = {}, cur_seq = {} , payload = {}  ".format(counter,seq_num,ip.len,cur_seq,payload))
print("\n<EOF> \nFinal Hash = {},".format(file_hash.hexdigest()))
