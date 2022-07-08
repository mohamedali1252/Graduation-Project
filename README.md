# HoneyPots
1. SSH:  
Secure shell protocol is a protocol to transfer data between two hosts in encrypted mode to protect the data from attackers.  
The Code of the SSH HP is written in python, the requried modules is:  
- **paramiko** using `pip install paramiko`
- **logging** using `pip install logging`  
Before running SSH honeypot, a key must be generated using the following command:  
`ssh-keygen -t rsa -f server.key` and then rename the output file using `mv server.key.pub server.pub`  
After running the SSH honeypot **features.log** file will be created and file called **ssh_honeypot.log**, this file contain the logs about each connection to the honeypot.  
Exapmle of the **features.log** file:  
![alt text](Images/ssh-ex.JPG)  
The file called **ssh_honeypot.log** has the every command The attacker write in the shell  
![alt text](Images/ssh_honey.JPG)  
2. FTP: 
File Transfer Protocol is a protocol to transfer files between machines on the same network.  
The Code of the FTP HP is written in python, the requried modules is:  
- **pickle** using `pip install pickle-mixin`  
- **twisted** using `pip install Twisted`  
- **pyshark** using `pip install pyshark`  
After running FTP HP file named **ftplog.txt** will be created and it has the information about the each connection has occurred.  
Exapmle of the **ftplog.txt** file:  
![alt text](Images/ftp-ex.JPG) 





