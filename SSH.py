#!/usr/bin/python3
import argparse
import threading
import socket
import sys
import os
import traceback
from logger import logging
import json
import paramiko
from datetime import datetime
from binascii import hexlify
from paramiko.py3compat import b, u, decodebytes
from random import random
from random import randint
import time



HOST_KEY = paramiko.RSAKey(filename='server.key')
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"

UP_KEY = '\x1b[A'.encode()
DOWN_KEY = '\x1b[B'.encode()
RIGHT_KEY = '\x1b[C'.encode()
LEFT_KEY = '\x1b[D'.encode()
BACK_KEY = '\x7f'.encode()

logging.basicConfig( #to provide the logging info that we recieve from the attacker
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='ssh_honeypot.log')


def ping(command):
	cmd = command
	#response=""
	result = cmd.split()
	host = result[1]
	response = "PING " +str(host) +" 56(84) bytes of data.\n"
	for i in range(0,4):
		time.sleep(2/100)
		time_ping = str((random() * 10) + 20)
		ttl = str((randint(0,5) * 10))
		response += "64 bytes from" + host +" : icmp_seq=" + str(i) +" ttl=" + ttl +" time=" + time_ping + "ms\n"
	return response
	


def Ls(command):
	response=""
	etc = "acpi                           ec2_version         libpaper.d      overlayroot.conf         services\n" + "adduser.conf                   emacs               lighttpd        overlayroot.local.conf   sgml\n" +"alternatives                   environment         locale.alias    pam.conf                 shadow\n" + "apache2                        fonts               locale.gen      pam.d                    shadow-\n" + "apm                            fstab               localtime       papersize                shells\n" + "apparmor                       fuse.conf           logcheck        passwd                   siege\n" +"apparmor.d                     gai.conf            login.defs      passwd-                  skel\n" + "apport                         groff               logrotate.conf  perl                     sos.conf\n" +"apt                            group               logrotate.d     pm                       ssh\n" + "at.deny                        group-              lsb-release     polkit-1                 ssl\n" + "audisp                         grub.d              ltrace.conf     pollinate                subgid\n" + "audit                          gshadow             lvm             popularity-contest.conf  subgid-\n" + "bash.bashrc                    gshadow-            machine-id      ppp                      subuid\n" + "bash_completion                gss                 magic           profile                  subuid-\n" + "bash_completion.d              gtk-2.0             magic.mime      profile.d                subversion\n" + "bindresvport.blacklist         hdparm.conf         mailcap         protocols                sudoers\n" + "binfmt.d                       host.conf           mailcap.order   proxychains.conf         sudoers.d\n" + "byobu                          hostname            manpath.config  python                   supervisor\n" + "ca-certificates                hosts               mdadm           python2.7                sysctl.conf\n" + "ca-certificates.conf           hosts.allow         memcached.conf  python3                  sysctl.d\n" + "ca-certificates.conf.dpkg-old  hosts.deny          mime.types      python3.5                sysstat\n" + "calendar                       init                mke2fs.conf     rc0.d                    systemd\n" + "checkinstallrc                 init.d              modprobe.d      rc1.d                    terminfo\n" + "cloud                          initramfs-tools     modules         rc2.d                    timezone\n" + "colordiffrc                    inputrc             modules-load.d  rc3.d                    tmpfiles.d\n" + "console-setup                  insserv             mtab            rc4.d                    tor\n" + "cron.d                         insserv.conf        mysql           rc5.d                    ucf.conf\n" + "cron.daily                     insserv.conf.d      node  rc6.d                    udev\n" + "cron.hourly                    iproute2            nanorc          rc.local                 ufw "

	fake_fs = "bin   etc   initrd.img.old  lost+found  openvpn-ca  root  snap  tmp var  volume\n" + "boot  home        lib             media       opt         run   srv  vmlinuz\n" + "dev   initrd.img  lib64           mnt         proc        sbin  sys   usr       vmlinuz.old"
	cmd = command
	if cmd=="ls":
		response = "users.txt"
	else:
		result = cmd.split()
		dir_file = result[1]
		if dir_file == "/root" or dir_file == "/" :
			response = fake_fs 
		if dir_file== "/etc":
			response = etc
	return response
	
	
	
def cat(command) :
	cmd = command
	result = cmd.split()
	file = result[1]
	response = ""
	s = "fake_files/" + file
	if file == "data" or file == "export2.csv" or file == "start-up.sh" or file=="users.txt":
		b = open(s,"r")
		content = b.read()
		response = content
	else:
		response = "File not found"
	return response
	
	
def ifconfig():
	response = "ens3      Link encap:Ethernet  HWaddr fa:16:3e:ea:69:d3\n" + "          inet addr:192.168.0.3  Bcast:192.168.0.255  Mask:255.255.255.0\n" + "          inet6 addr: fe80::f816:3eff:feea:69d3/64 Scope:Link\n" + "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n" + "          RX packets:0 errors:0 dropped:0 overruns:0 frame:0\n" + "          TX packets:2 errors:0 dropped:0 overruns:0 carrier:0\n" + "          collisions:0 txqueuelen:0\n" + "          RX bytes:0 (0.0 B)  TX bytes:180 (180.0 B)\n\n" + "lo        Link encap:Local Loopback \n" + "          inet addr:127.0.0.1  Mask:255.0.0.0 \n" + "          inet6 addr: ::1/128 Scope:Host \n" + "          UP LOOPBACK RUNNING  MTU:65536  Metric:1 \n" + "          RX packets:237 errors:0 dropped:0 overruns:0 frame:0 \n" + "          TX packets:237 errors:0 dropped:0 overruns:0 carrier:0 \n" + "          collisions:0 txqueuelen:1 \n" + "          RX bytes:16818 (16.8 KB)  TX bytes:16818 (16.8 KB) \n"
	return response
	
def ipa():
	response = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1\n" + "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n" + "    inet 127.0.0.1/8 scope host lo\n" + "       valid_lft forever preferred_lft forever\n" + "    inet6 ::1/128 scope host\n" + "       valid_lft forever preferred_lft forever\n" + "2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n" + "    link/ether fa:16:3e:d6:f2:dd brd ff:ff:ff:ff:ff:ff\n" + "    inet 192.168.0.183/24 brd 192.168.0.255 scope global ens3\n" + "       valid_lft forever preferred_lft forever\n" + "    inet6 fe80::f816:3eff:fed6:f2dd/64 scope link\n" + "       valid_lft forever preferred_lft forever \n"
	return response
def handle_cmd(cmd, chan, ip,port):
    response = ""
    if cmd.startswith("ls"):
        response = Ls(cmd)
    if cmd.startswith("pwd"):
        response = "/home/root"
    if cmd.startswith("ping"):
        response = ping(cmd)
    if cmd.startswith("echo"):
    	command = cmd
    	command = command.split()
    	response = command[1]
    if cmd.startswith("cat"):
    	response = cat(cmd)
    if cmd.startswith("ifconfig"):
    	response = ifconfig()
    if cmd.startswith("ip a"):
    	response = ipa()
    if response != '':
        logging.info('Response from honeypot ({},{}): '.format(ip,port,response))
        response = response + "\r\n"
    chan.send(response)


class BasicSshHoneypot(paramiko.ServerInterface):
    client_ip = None

    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        logging.info('client called check_channel_request ({}): {}'.format(
            self.client_ip, kind))
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        logging.info('client called get_allowed_auths ({}) with username {}'.format(
            self.client_ip, username))
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        fingerprint = u(hexlify(key.get_fingerprint()))
        logging.info(
            'client public key ({}): username: {}, key name: {}, md5 fingerprint: {}, base64: {}, bits: {}'.format(
                self.client_ip, username, key.get_name(), fingerprint, key.get_base64(), key.get_bits()))
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def check_auth_password(self, username, password):
        # Accept all passwords as valid by default
        logging.info('new client credentials ({}): username: {}, password: {}'.format(
            self.client_ip, username, password))
        if password == "test": #set the needed  password
        	return paramiko.AUTH_SUCCESSFUL
        else:
        	return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel,username, command):
        command_text = str(command.decode("utf-8"))

        logging.info('client sent command via check_channel_exec_request ({}): {}'.format(
            self.client_ip, username, command))
        return True


def handle_connection(client, addr):
    client_ip = addr[0]
    client_port = addr[1]
    logging.info('New connection from: {}, port : {}'.format(client_ip,client_port))

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        transport.local_version = SSH_BANNER  # Change banner to appear more convincing
        server = BasicSshHoneypot(client_ip)
        try:
            transport.start_server(server=server)

        except paramiko.SSHException:
            print('*** SSH negotiation failed.')
            raise Exception("SSH negotiation failed")

        # wait for auth
        chan = transport.accept(10)
        if chan is None:
            print('*** No channel (from ' + client_ip+' , '+ client_port + ').')
            raise Exception("No channel")

        chan.settimeout(20) #time to end the ssh connection if there is no interaction

        if transport.remote_mac != '':
            logging.info('Client mac ({},{}): {}'.format(client_ip,client_port ,transport.remote_mac))

        if transport.remote_compression != '':
            logging.info('Client compression ({},{}): {}'.format(client_ip, client_port,transport.remote_compression))

        if transport.remote_version != '':
            logging.info('Client SSH version ({},{}): {}'.format(client_ip, client_port, transport.remote_version))

        if transport.remote_cipher != '':
            logging.info('Client SSH cipher ({},{}): {}'.format(client_ip, client_port,transport.remote_cipher))

        server.event.wait(10)
        if not server.event.is_set():
            logging.info('** Client ({},{}): never asked for a shell'.format(client_ip,client_port))
            raise Exception("No shell request")

        try:
            chan.send("Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-128-generic x86_64)\r\n\r\n")
            run = True
            while run:
                chan.send("$ ")
                command = ""
                while not command.endswith("\r"):
                    transport = chan.recv(1024)
                    print(client_ip + "- received:", transport)
                    # Echo input to psuedo-simulate a basic terminal
                    if (
                            transport != UP_KEY
                            and transport != DOWN_KEY
                            and transport != LEFT_KEY
                            and transport != RIGHT_KEY
                            and transport != BACK_KEY
                    ):
                        chan.send(transport)
                        command += transport.decode("utf-8")

                chan.send("\r\n")
                command = command.rstrip()
                logging.info('Command receied ({},{}): {}'.format(client_ip, client_port,command))
                #detect_url(command, client_ip)

                if command == "exit" or command == "quit" or command == "logout":
                    #settings.addLogEntry("Connection closed (via exit command): " + client_ip + "\n")
                    run = False

                else:
                    handle_cmd(command, chan, client_ip,client_port)

        except Exception as err:
            print('!!! Exception: {}: {}'.format(err.__class__, err))
            try:
                transport.close()
            except Exception:
                pass

        chan.close()

    except Exception as err:
        print('!!! Exception: {}: {}'.format(err.__class__, err))
        try:
            transport.close()
        except Exception:
            pass


def start_server(port, bind):
    """Init and run the ssh server"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, port))
    except Exception as err:
        print('*** Bind failed: {}'.format(err))
        traceback.print_exc()
        sys.exit(1)

    threads = []
    while True:
        try:
            sock.listen(100)
            print('Listening for connection ...')
            client, addr = sock.accept()
        except Exception as err:
            print('*** Listen/accept failed: {}'.format(err))
            traceback.print_exc()
        new_thread = threading.Thread(target=handle_connection, args=(client, addr))
        new_thread.start()
        threads.append(new_thread)

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run an SSH honeypot server')
    parser.add_argument("--port", "-p", help="The port to bind the ssh server to (default 22)", default=2222, type=int,
                        action="store")
    parser.add_argument("--bind", "-b", help="The address to bind the ssh server to", default="", type=str,
                        action="store")
    args = parser.parse_args()
    start_server(args.port, args.bind)