# Design:  
Intelligence HoneyPots on SDN:  
Our design is having 3 hosts, openflow switch,RYU controller and Redis server  
![alt text](src/System.JPG)  
One of the hosts have the HoneyPots, capture the traffic, feature extraction and upload it to Redis server.  
The controller have the ML model and UI to show the actions have been taken.  
Hosts can be physical hosts if you are using openflow switch, in our case we are using mininet so it's a virtual hosts.  
# HoneyPots:  
*It exists on the Host*  
1. SSH:  
Secure shell protocol is a protocol to transfer data between two hosts in encrypted mode to protect the data from attackers.  
The Code of the SSH HP is written in python, the requried modules is:   
- **paramiko** using `pip install paramiko`  
- **logging** using `pip install logging`  
Before running SSH honeypot, a key must be generated using the following command:  
`ssh-keygen -t rsa -f server.key` and then rename the output file using `mv server.key.pub server.pub`  
After running the SSH honeypot **features.log** file will be created and file called **ssh_honeypot.log**, this file contain the logs about each connection to the honeypot.  
Exapmle of the **features.log** file:  
![alt text](src/ssh-ex.JPG)  
The file called **ssh_honeypot.log** has the every command The attacker write in the shell.  
To Run the SSH HoneyPot you should use `python3 SSH.py` and you should have the folder named **fake_files**.  
![alt text](src/ssh_honey.JPG)  
2. FTP:  
File Transfer Protocol is a protocol to transfer files between machines on the same network.  
The Code of the FTP HP is written in python, the requried modules is:  
- **pickle** using `pip install pickle-mixin`  
- **twisted** using `pip install Twisted`  
- **pyshark** using `pip install pyshark`  
After running FTP HP file named **ftplog.txt** will be created and it has the information about the each connection has occurred.  
Exapmle of the **ftplog.txt** file:  
![alt text](src/ftp-ex.JPG)  
To Run the FTP Honeypot you should use  
- `python3 ftppot.py`  
3. SMTP:  
Simple Mail Transfer Protocol is a protocol for transfer the mails from one machine to other using  telnet.  

# Zeek:  
*It exists on the Host*  
You must install zeek using the following command:  
- `sudo apt-get -y install zeek`  
To run zeek then you must give it a pcap file so we used **tcpdump** tool to capture the traffic using:  
- `tcpdump -i <interface-name> -s 0 -w <filename>`, in this case the file name is **ntraffic.pcap**.  
After capturing the traffic, we will use zeek script called **extract.zeek**that extract some of the required features and store it in a file called **conn.list** using the following command:  
- `zeek -r ntraffic.pcap extract.zeek -C > conn.list`  
After getting **conn.list** file, we must sort it with the id of the connection using:  
- `sort -n conn.list > conn_sort.list`  
Exapmle of the **conn_sort.list** file:  
![alt text](src/conn_sort.JPG) 
# Feature Extraction:  
*It exists on the Host*  
The training Dataset for the model is KDD dataset which has 41 features.
Some of this features from the log files and some of them is from the traffic of the connections,
so we used zeek tool to extract some of the features and then link the features extracted from zeek and the log files using the pyhton program called **editor.py**.  
- You must have the file called **tablethree_editor.py** when running it.  
To Run the script we will use the following command:  
- `python3 editor.py`  
Files called **con_feature.txt** and **ips.txt** will be created that have the ssh,ftp, and the smtp connections only and the IPs.  

# Redis:  
*It exists on the Host and the controller*  
To install redis server we will use the following commands:  
- ``  
- ``  
To install redis module for python we will use the following command:  
- `pip install redis`  
There is a python script to upload the files **con_feature.txt** and **ips.txt** for the ML model.  
We will use the python program called **store.py** to do that.  
To run the file that store data on the database we will use the following command:  
- `python3 store.py <ip-of-the-server-run-redis-server>`  
On the side of the ML model we will use **readfrom_db.py** to save the data on the machine.  
Two files called **con_feature.txt** and **ips.txt** will be created after running the script using:  
- `python3 readfrom_db`  


# Mininet:  
*It exists on the Host*  
To install mininet on your machine, you can use the following command:  
- `sudo apt-get -y install mininet`  
To use mininet, you can type:  
- `service openvswitch-switch start` to start the openflow switch.  
- `sudo mn --controller=remote,ip=127.0.0.1 --switch=ovsk,protcols=OpenFlow13 --topo=minimal` to start the mininet with **minimal** topology with 2 hosts and remote controller.  
Inside the mininet, you can type `xterm h1` to get a terminal for host1.  
We used a custom topology written in python, to run the topology:  
- `sudo python3 topo.py`  
You will get 3 hosts with mac addresses and IPs, and NAT so we can connect to the internet.  


# Controller:  
To install RYU controller:  
- `git clone https://github.com/faucetsdn/ryu.git` to clone the repo have the ryu controller.  
- `cd ryu`
- `sudo pip install -r tools/pip-requires` to install the requried modules
- `sudo python3 setup.py install`  
Now you have the ryu controller with all the Applications of it. After download  the **simple_switch_13.py** you will change directory to where the file exist and run the Applications using:  
- `ryu-manager --verbose simple_switch_13`  


# Machine Learning model:  
*It exists on the contoller*  
To run the ML model, you must have the following modules:  
- numpy, you can install it using `pip install numpy`
- pandas, you can install it using `pip install pandas`
- sklearn, you can install it using `pip install sklearn`
- keras, you can install it using `pip install keras`  
You must have **kdd_train.csv**, and **kdd_test.csv** in the same folder where you will run the model.  
You can run the model using:  
- `python3 Model.py`  
After that you can predict using the **classifier.py** but you must have the following modules:  
- tensorflow, you can install using `pip install tensorflow`  
Now you can run the classifier using:
- `python3 classifier.py`  


# UI:  
*It exists on the contoller*  
You must have the following modules:  
- pyqt6, you can install it using `pip install pyqt6`.  
Now you can run the UI using:
- `python3 main.py`
There is optional info inside the file called "global_var.py" you will find different variable with explicit names.  
Exapmle of the UI:  
![alt text](src/UI.png) 
