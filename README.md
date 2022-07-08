# HoneyPots
1. SSH:  
Secure shell protocol is a protocol to transfer data between two hosts in encrypted mode to protect the data from attackers.  
The Code of the SSH HP is written in python, the requried modules is:  
- **paramiko** using `pip install paramiko`
- **logging** using `pip install logging`
Before running SSH honeypot, a key must be generated using the following command:  
`ssh-keygen -t rsa -f server.key` and then rename the output file using `mv server.key.pub server.pub`  
When running the SSH honeypot **features.log** file will be created, this file contain the logs about each connection to the honeypot.  



