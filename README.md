
# Installation
At this time, everything should be included in a Linux python environment. Simply follow the usage instructions. 

**NOTE:** To get all of the features out of the schizo module, users may wish to install the python-libemu module, but Mailoney will run with out it. 

# Usage

```
usage: mailoney.py [-h] [-i <ip address>] [-p <port>] -s mailserver -t
                   {open_relay,postfix_creds,schizo_open_relay}

Command line arguments

optional arguments:
  -h, --help            show this help message and exit
  -i <ip address>       The IP address to listen on
  -p <port>             The port to listen on
  -s mailserver         A Name that'll show up as the mail server name
  -t {open_relay,	Type of Honeypot 
  	postfix_creds,
  	schizo_open_relay}
```
### Types
Right now there are three types of Modules for Mailoney. 
- open_relay - Just a generic open relay, will attempt to log full text emails attempted to be sent. 
- postfix_creds - This module simply logs credentials from logon attempts. 
- schizo_open_relay - This module logs everything, developed by [@botnet_hunter](https://twitter.com/botnet_hunter)

# Running 
SMTP ports 25, 465, 587 are privileged ports and therefore require elevated permissions (i.e. Sudo). It is probaby not a good idea to run your honeypot with elevated permissions. As such, I **strongly** encourage you to use port forwarding. 

Setting this up is easy, lets say we want to run Mailoney on port 2525 (a nice non-priveleged port). 
#### IPTables example
We can redirect port 25 to port 2525 with IPtables:
`$ sudo iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 2525`

