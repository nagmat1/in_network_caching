# IN-NETWORK CACHING FOR FAST FILE RECOVERY

The application can only correctly function on Linux-based operating systems due to several Linux-based functional dependencies. 

Before starting the process be sure that P4SDE is installed correctly. 

# Usage

1. Compile the in_network_caching.p4 by : 
```
./tools/p4_build.sh ~/mysde/exercises/12_mirroarping/in_network_caching.p4
```
2. Load the program on the programmable switch by : 
```
./run_switchd.sh -p in_network_caching
```
3. Run the bfrt python scripts : 
```
./run_bfshell.sh -b ./exercises/12_mirroarping/setup.py 
```
4. Run the tcpcapture to file : 
```
tcpdump -s 65535 -v -i enp2s0 -nn -B 544096 -w dtn4.pcap
```
5. Run the receiver python socket : 
```
python3 socket_receive_file.py
```
6. Run the sender python socket : 
```
python3 socket_send_file.py 192.168.1.1 10GB_file.txt
```
7. Trigger the parsing in while transfer is being done : 
```
cmd = 'sudo python3 /home/nnazarov/exper/converter/taze_ver_dpkt.py > /home/nnazarov/exper/converter/results.txt 2> errors.log &'
p = subprocess.Popen([cmd],shell=True)
```
