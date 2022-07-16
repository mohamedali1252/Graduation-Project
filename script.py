import os
import subprocess
import sys
import threading
import csv
import shutil


interface = "h2-eth0" #default value if there is no inputs for the interface
dur = 120

if len(sys.argv) == 2:
	ip = sys.argv[1]
elif len(sys.argv) == 3:
	ip = sys.argv[1]
	interface = sys.argv[2]
elif len(sys.argv) == 4:
	ip = sys.argv[1]
	interface = sys.argv[2]
	dur = sys.argv[3]



def running_dump():
	global interface,dur
	cmd1 = "zeek -r ntraffic.pcap extract.zeek -C > conn.list"
	cmd2 = "sort -n conn.list > conn_sort.list"
	cmd3 = "python3 editor.py"
	cmd4 = "python3 store.py " + ip
	p1 = subprocess.run(['timeout', dur, "tcpdump", "-i",interface,"-s","0", "-w","ntraffic.pcap"])
	os.system(cmd1)
	os.system(cmd2)
	lines_after = []
	reader = open("conn_sort.list","r")
	lines = reader.readlines()
	reader.close()
	for line in lines:
		line1 = line.strip("\n")
		line_split = line1.split(",")
		if line_split[8] == "ssh" or line_split[8] == "ftp" or line_split[8] == "smtp":
	          	lines_after.append(line)
	writer = open("conn_sort.list","w")
	for line in lines_after:
		writer.write(line)
	writer.close()
	f = open("conn_sort.list","r")
	count = 0
	conn_sort = f.readlines()
	filtered = []
	for line in conn_sort:
	          line1 = line.rstrip('/n')
	          line1 = line1.split(",")
	          duration = line1[6]
	          con_type = line1[8]
	          flag = line1[10]
	          src_bytes = line1[11]
	          dst_bytes = line1[12]
	          land = line1[13]
	          wrong_fragment = line1[14]
	          urgent = line1[15]
	          if duration == "0" and (con_type == "ssh" or con_type == "ftp" or con_type == "smtp") and flag =="RSTO" and src_bytes == "0" and dst_bytes == "0" and land == "0" and wrong_fragment == "0" and urgent == "0":
	                    count +=1
	          else:
	                    filtered.append(line)
	f.close()
	f = open("conn_sort.list","w")
	for line in filtered:
	          f.write(line)
	f.close()
	os.system(cmd3)
	os.system(cmd4)
	print("Storing Ecexcuted")
	
def running_ssh():
	p2 = subprocess.run(['python3', "SSH.py"])

def running_ftp():
	p3 = subprocess.run(['python3', "ftppot.py"])

def running_smtp():
	p3 = subprocess.run(['python3', "mailoney.py","-i", "10.0.0.2" ,"-p", "25","-t", 'open_relay'])

thread1 = threading.Thread(target=running_dump)
thread1.start()

thread2 = threading.Thread(target=running_ssh)
thread2.start()


thread3 = threading.Thread(target=running_ftp)
thread3.start()

thread3 = threading.Thread(target=running_smtp)
thread3.start()

