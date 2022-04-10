#!/usr/bin/python3
import argparse
import threading
import socket
import sys
import os
import traceback
import logging
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

logging.basicConfig(  # to provide the logging info that we recieve from the attacker
    filename="ssh_honeypot.log",
    filemode='a',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)

logger = logging.getLogger('logger')


def setup_logger(logger_name, log_file, level=logging.DEBUG):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(message)s')
    fileHandler = logging.FileHandler(log_file, mode='a')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)

    l.setLevel(level)
    l.addHandler(fileHandler)
    l.addHandler(streamHandler)


setup_logger('log2', "feature.log")
logger_2 = logging.getLogger('log2')


def ping(command):
    cmd = command
    # response=""
    result = cmd.split()
    host = result[1]
    response = "PING " + str(host) + " 56(84) bytes of data.\n"
    for i in range(0, 4):
        time.sleep(2 / 100)
        time_ping = str((random() * 10) + 20)
        ttl = str((randint(0, 5) * 10))
        response += "64 bytes from" + host + " : icmp_seq=" + str(i) + " ttl=" + ttl + " time=" + time_ping + "ms\n"
    return response


def Ls(command):
    response = ""
    etc = "acpi                           ec2_version         libpaper.d      overlayroot.conf         services\n\r" + "adduser.conf                   emacs               lighttpd        overlayroot.local.conf   sgml\n\r" + "alternatives                   environment         locale.alias    pam.conf                 shadow\n\r" + "apache2                        fonts               locale.gen      pam.d                    shadow-\n\r" + "apm                            fstab               localtime       papersize                shells\n\r" + "apparmor                       fuse.conf           logcheck        passwd                   siege\n\r" + "apparmor.d                     gai.conf            login.defs      passwd-                  skel\n\r" + "apport                         groff               logrotate.conf  perl                     sos.conf\n\r" + "apt                            group               logrotate.d     pm                       ssh\n\r" + "at.deny                        group-              lsb-release     polkit-1                 ssl\n\r" + "audisp                         grub.d              ltrace.conf     pollinate                subgid\n\r" + "audit                          gshadow             lvm             popularity-contest.conf  subgid-\n\r" + "bash.bashrc                    gshadow-            machine-id      ppp                      subuid\n\r" + "bash_completion                gss                 magic           profile                  subuid-\n\r" + "bash_completion.d              gtk-2.0             magic.mime      profile.d                subversion\n\r" + "bindresvport.blacklist         hdparm.conf         mailcap         protocols                sudoers\n\r" + "binfmt.d                       host.conf           mailcap.order   proxychains.conf         sudoers.d\n\r" + "byobu                          hostname            manpath.config  python                   supervisor\n\r" + "ca-certificates                hosts               mdadm           python2.7                sysctl.conf\n\r" + "ca-certificates.conf           hosts.allow         memcached.conf  python3                  sysctl.d\n\r" + "ca-certificates.conf.dpkg-old  hosts.deny          mime.types      python3.5                sysstat\n\r" + "calendar                       init                mke2fs.conf     rc0.d                    systemd\n\r" + "checkinstallrc                 init.d              modprobe.d      rc1.d                    terminfo\n\r" + "cloud                          initramfs-tools     modules         rc2.d                    timezone\n\r" + "colordiffrc                    inputrc             modules-load.d  rc3.d                    tmpfiles.d\n\r" + "console-setup                  insserv             mtab            rc4.d                    tor\n\r" + "cron.d                         insserv.conf        mysql           rc5.d                    ucf.conf\n\r" + "cron.daily                     insserv.conf.d      node  rc6.d                    udev\n\r" + "cron.hourly                    iproute2            nanorc          rc.local                 ufw "

    fake_fs = "bin   etc   initrd.img.old  lost+found  openvpn-ca  root  snap  tmp var  volume\n\r" + "boot  home        lib             media       opt         run   srv  vmlinuz\n\r" + "dev   initrd.img  lib64           mnt         proc        sbin  sys   usr       vmlinuz.old"
    cmd = command
    if cmd == "ls":
        response = "users.txt"
    else:
        result = cmd.split()
        dir_file = result[1]
        if dir_file == "/root" or dir_file == "/":
            response = fake_fs
        if dir_file == "/etc":
            response = etc
    return response


def cat(command):
    cmd = command
    result = cmd.split()
    file = result[1]
    response = ""
    s = "fake_files/" + file
    if file == "data" or file == "export2.csv" or file == "start-up.sh" or file == "users.txt":
        b = open(s, "r")
        content = b.read()
        response = content
    else:
        response = "File not found"
    return response


def ifconfig():
    response = "ens3: Link encap:Ethernet  HWaddr fa:16:3e:ea:69:d3\n\r" + "        inet addr:192.168.0.3  Bcast:192.168.0.255  Mask:255.255.255.0\n\r" + "        inet6 addr: fe80::f816:3eff:feea:69d3/64 Scope:Link\n\r" + "        UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n\r" + "        RX packets:0 errors:0 dropped:0 overruns:0 frame:0\n\r" + "        TX packets:2 errors:0 dropped:0 overruns:0 carrier:0\n\r" + "        collisions:0 txqueuelen:0\n\r" + "        RX bytes:0 (0.0 B)  TX bytes:180 (180.0 B)\n\r\n\r" + "lo: Link encap:Local Loopback \n\r" + "        inet addr:127.0.0.1  Mask:255.0.0.0 \n\r" + "        inet6 addr: ::1/128 Scope:Host \n\r" + "        UP LOOPBACK RUNNING  MTU:65536  Metric:1 \n\r" + "        RX packets:237 errors:0 dropped:0 overruns:0 frame:0 \n\r" + "        TX packets:237 errors:0 dropped:0 overruns:0 carrier:0 \n\r" + "        collisions:0 txqueuelen:1 \n\r" + "        RX bytes:16818 (16.8 KB)  TX bytes:16818 (16.8 KB) \n\r"
    return response


def ipa():
    response = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1\n\r" + "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n\r" + "    inet 127.0.0.1/8 scope host lo\n\r" + "       valid_lft forever preferred_lft forever\n\r" + "    inet6 ::1/128 scope host\n\r" + "       valid_lft forever preferred_lft forever\n\r" + "2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n\r" + "    link/ether fa:16:3e:d6:f2:dd brd ff:ff:ff:ff:ff:ff\n\r" + "    inet 192.168.0.183/24 brd 192.168.0.255 scope global ens3\n\r" + "       valid_lft forever preferred_lft forever\n\r" + "    inet6 fe80::f816:3eff:fed6:f2dd/64 scope link\n\r" + "       valid_lft forever preferred_lft forever \n\r"
    return response


def uname():
    response = "Linux\n\r"
    return response


def whoami():
    response = "Ubuntu 18.04.4\n\r"
    return response


def hostname():
    response = "Ubuntu 18.04.4\n\r"
    return response


def route():
    response = "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n\r" + "default         192.168.1.2     0.0.0.0         UG    1024   0        0 eth0\n\r" + "192.168.1.0     *               255.255.255.0   U     0      0        0 eth0\n\r"
    return response


def ps():
    response = "PID   TTY          TIME CMD\n\r12330 pts/0    00:00:00 bash\n\r21621 pts/0    00:00:00 ps"
    return response


def psaux():
    response = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n\rroot         1  0.0  0.0    892   572 ?        Sl   Nov28   0:00 /init\r\nroot       227  0.0  0.0    900    80 ?        Ss   Nov28   0:00 /init\n\rroot       228  0.0  0.0    900    88 ?        S    Nov28   0:00 /init\n\rzaphod     229  0.0  0.1 749596 31000 pts/0    Ssl+ Nov28   0:15 docker\n\rroot       240  0.0  0.0      0     0 ?        Z    Nov28   0:00 [init] <defunct>\n\rroot       247  0.0  0.0    900    88 ?        S    Nov28   0:00 /init\n\rroot       248  0.0  0.1 1758276 31408 pts/1   Ssl+ Nov28   0:10 /mnt/wsl/docker-desktop/docker-desktop-proxy\n\rroot       283  0.0  0.0    892    80 ?        Ss   Dec01   0:00 /init\n\rroot       284  0.0  0.0    892    80 ?        R    Dec01   0:00 /init\n\rzaphod     285  0.0  0.0  11964  5764 pts/2    Ss   Dec01   0:00 -zsh\n\rzaphod     343  0.0  0.0  23764  9836 pts/2    T    17:44   0:00 vi foo\n\rroot       349  0.0  0.0    892    80 ?        Ss   17:45   0:00 /init\n\rroot       350  0.0  0.0    892    80 ?        S    17:45   0:00 /init\n\rzaphod     351  0.0  0.0  11964  5764 pts/3    Ss+  17:45   0:00 -zsh\n\rzaphod     601  0.0  0.0  10612  3236 pts/2    R+   18:24   0:00 ps aux"
    return response


def netstat():
    response = "UDP\n\r \n\r      udpInDatagrams      =  39228     udpOutDatagrams     =  2455\n\r       udpInErrors         =     0\n\r \n\rTCP\n\r \n\r      tcpRtoAlgorithm     =     4      tcpMaxConn          =    -1\n\r      tcpRtoMax           = 60000      tcpPassiveOpens     =     2\n\r      tcpActiveOpens      =     4      tcpEstabResets      =     1\n\r      tcpAttemptFails     =     3      tcpOutSegs          =   315\n\r      tcpCurrEstab        =     1      tcpOutDataBytes     = 10547\n\r     tcpOutDataSegs      =   288      tcpRetransBytes     =  8376\n\r      tcpRetransSegs      =    29      tcpOutAckDelayed    =    23\n\r      tcpOutAck           =    27      tcpOutWinUpdate     =     2\n\r      tcpOutUrg           =     2      tcpOutControl       =     8\n\r      tcpOutWinProbe      =     0      tcpOutFastRetrans   =     1\n\r      tcpOutRsts          =     0\n\r      tcpInSegs           =   563      tcpInAckBytes       = 10549\n\r      tcpInAckSegs        =   289      tcpInAckUnsent      =     0\n\r      tcpInDupAck         =    27      tcpInInorderBytes   =   673\n\r      tcpInInorderSegs    =   254      tcpInInorderBytes   =   673\n\r      tcpInUnorderSegs    =     0      tcpInUnorderBytes   =     0\n\r      tcpInDupSegs        =     0      tcpInDupBytes       =     0\n\r      tcpInPartDupSegs    =     0      tcpInPartDupBytes   =     0\n\r      tcpInPastWinSegs    =     0      tcpInPastWinBytes   =     0\n\r      tcpInWinProbe       =     0      tcpInWinUpdate      =   237    \n\r      tcpInClosed         =     0      tcpRttNoUpdate      =    21\n\r      tcpRttUpdate        =   266      tcpTimRetrans       =    26\n\r      tcpTimRetransDrop   =     0      tcpTimKeepalive     =     0\n\r      tcpTimKeepaliveProbe=     0      tcpTimKeepaliveDrop =     0\n\r \n\rIP\n\r \n\r      ipForwarding        =     2      ipDefaultTTL        =   255\n\r      ipInReceives        =  4518      ipInHdrErrors       =     0\n\r      ipInAddrErrors      =     0      ipInCksumErrs       =     0\n\r      ipForwDatagrams     =     0      ipForwProhibits     =     0\n\r      ipInUnknownProtos   =     0      ipInDiscards        =     0\n\r      ipInDelivers        =  4486      ipOutRequests       =  2805\n\r      ipOutDiscards       =     5      ipOutNoRoutes       =     0\n\r      ipReasmTimeout      =    60      ipReasmReqds        =     2\n\r      ipReasmOKs          =     2      ipReasmReqds        =     2\n\r      ipReasmDuplicates   =     0      ipReasmFails        =     0\n\r      ipFragOKs           =    20      ipReasmPartDups     =     0\n\r      ipFragCreates       =   116      ipFragFails         =     0\n\r      tcpInErrs           =     0      ipRoutingDiscards   =     0\n\r      udpInCksumErrs      =     0      udpNoPorts          =    33\n\r      rawipInOverflows    =     0      udpInOverflows      =     6\n\r \n\rICMP\n\r \n\r      icmpInMsgs          =     0      icmpInErrors        =     0\n\r      icmpInCksumErrs     =     0      icmpInUnknowns      =     0\n\r      icmpInDestUnreachs  =     0      icmpInTimeExcds     =     0\n\r      icmpInParmProbs     =     0      icmpInSrcQuenchs    =     0\n\r      icmpInRedirects     =     0      icmpInBadRedirects  =     0\n\r      icmpInEchos         =     0      icmpInEchoReps      =     0\n\r      icmpInTimestamps    =     0      icmpInTimestampReps =     0\n\r      icmpInAddrMasks     =     0      icmpInAddrMaskReps  =     0\n\r      icmpInFragNeeded    =     0      icmpOutMsgs         =     7\n\r      icmpOutDestUnreachs =     1      icmpOutErrors       =     0\n\r      icmpOutDrops        =     5      icmpOutTimeExcds    =     0\n\r      icmpOutParmProbs    =     0      icmpOutSrcQuenchs   =     6\n\r      icmpOutRedirects    =     0      icmpOutEchos        =     0\n\r      icmpOutEchoReps     =     0      icmpOutTimestamps   =     0\n\r      icmpOutTimestampReps=     0      icmpOutAddrMasks    =     0\n\r      icmpOutAddrMaskReps =     0      icmpOutFragNeeded   =     0\n\r      icmpInOverflows     =     0\n\r \n\r \n\rIGMP:\n\r \n\r0 messages received\n\r0 messages received with too few bytes\n\r0 messages received with bad checksum\n\r0 membership queries received\n\r0 membership queries received with invalid field(s)\n\r0 membership reports received\n\r0 membership reports received with invalid field(s)\n\r0 membership reports received for groups to which we belong\n\r0 membership reports sent"
    return response


def handle_cmd(cmd, chan, ip, port):
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
    if cmd.startswith("uname"):
        response = uname()
    if cmd.startswith("whoami"):
        response = whoami()
    if cmd.startswith("hostname"):
        response = hostname()
    if cmd.startswith("route"):
        response = route()
    if cmd.startswith("ps"):
        response = ps()
    if cmd.startswith("ps aux"):
        response = psaux()
    if cmd.startswith("netstat"):
        response = netstat()
    #############################
    if cmd.startswith("su root"):
        response = "su: Authentication failure"
    if cmd.startswith(">"):
        response = ""
    if cmd.startswith("touch"):
        response = ""
    if cmd.startswith("echo"):
        response = ""

    if response != '':
        logger.info('Response from honeypot ({},{}): '.format(ip, port, response))
        response = response + "\r\n"
    chan.send(response)


class BasicSshHoneypot(paramiko.ServerInterface):
    client_ip = None
    client_port = None
    a_username = ""  # i use it to transfer the username to handel connetion function > by using server.a_username
    num_failed = 0  # i use to transfer it to handel connetion function > by using server.num_faild

    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        logger.info('client called check_channel_request ({},{}): {}'.format(
            self.client_ip, self.client_port, kind))
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        logger.info('client called get_allowed_auths ({},{}) with username {}'.format(
            self.client_ip, self.client_port, username))

        test = "publickey,password"
        return test

    def check_auth_publickey(self, username, key):
        fingerprint = u(hexlify(key.get_fingerprint()))
        logger.info(
            'client public key ({},{}): username: {}, key name: {}, md5 fingerprint: {}, base64: {}, bits: {}'.format(
                self.client_ip, self.client_port, username, key.get_name(), fingerprint, key.get_base64(),
                key.get_bits()))

        return paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def check_auth_password(self, username, password):
        # Accept all passwords as valid by default
        logger.info('new client credentials ({},{}): username: {}, password: {}'.format(
            self.client_ip, self.client_port, username, password))

        self.a_username = username  # to send it to handelconnection

        if str(password) == "test":  # set the needed  password
            return paramiko.AUTH_SUCCESSFUL
        else:
            self.num_failed = self.num_failed + 1
            print("here")

            return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, username, command):
        command_text = str(command.decode("utf-8"))

        logger.info('client sent command via check_channel_exec_request ({},{}): {}'.format(
            self.client_ip, self.client_port, username, command))
        return True

    # def get_username(self):


# return self.a_username;


def handle_connection(client, addr, port):
    client_ip = addr[0]
    client_port = addr[1]
    username = ""
    #######################
    date_time = 0
    src_ip = addr[0]
    src_port = addr[1]
    dst_ip = 0
    dst_port = 0
    hot = 0
    num_failed_login = 0
    logged_in = 0
    num_compromised_file = 0  # 3
    root_shell = 0
    su_attempted = 0
    num_root = 0  # if the username = root, if the command start with root and if su_attempted
    num_file_creations = 0
    num_shells = 1
    num_access_files = 0
    num_outbound_cmds = 0
    is_hot_login = 0
    is_guest_login = 0
    ##############################
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("127.0.0.1", 2222))
    local_ip = s.getsockname()[0]
    s.close()
    ############################
    # at release
    protocol_type = "tcp"
    service_type = "ssh"
    start = time.time()
    ##########start = now()
    land = 0
    dst_port = port
    dst_ip = local_ip

    if client_ip == local_ip or client_ip == "127.0.0.1" or client_ip == "127.0.0.2":
        if client_port == "2222" or client_port == port:
            land = 1

    logger.info(
        'New connection from: {}, port : {},to: {},land: {}'.format(client_ip, client_port, local_ip, str(land)))
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        transport.local_version = SSH_BANNER  # Change banner to appear more convincing
        server = BasicSshHoneypot(client_ip, client_port)

        try:
            transport.start_server(server=server)

        except paramiko.SSHException:
            print('*** SSH negotiation failed.')
            # num_failed_login = num_failed_login + 1

            raise Exception("SSH negotiation failed")

        # wait for auth
        chan = transport.accept(10)
        if chan is None:
            print('*** No channel (from ' + client_ip + ' , ' + client_port + ').')
            raise Exception("No channel")

        chan.settimeout(10)  # time to end the ssh connection if there is no interaction

        if transport.remote_mac != '':
            logger.info('Client mac ({},{}): {}'.format(client_ip, client_port, transport.remote_mac))

        if transport.remote_compression != '':
            logger.info('Client compression ({},{}): {}'.format(client_ip, client_port, transport.remote_compression))

        if transport.remote_version != '':
            logger.info('Client SSH version ({},{}): {}'.format(client_ip, client_port, transport.remote_version))

        if transport.remote_cipher != '':
            logger.info('Client SSH cipher ({},{}): {}'.format(client_ip, client_port, transport.remote_cipher))

        server.event.wait(10)
        if not server.event.is_set():
            logger.info('** Client ({},{}): never asked for a shell'.format(client_ip, client_port))
            num_shells = 0
            raise Exception("No shell request")
        try:
            username = server.a_username
            num_failed_login = server.num_failed
            if username == "root" or username == "Root":
                root_shell = 1
                num_root = num_root + 1

            if username == "root" or username == "Root" or username == "admin" or username == "Admin":
                is_hot_login = 1
            else:
                is_guest_login = 1

            logged_in = 1

            chan.send("Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-128-generic x86_64)\r\n\r\n")
            run = True
            while run:
                chan.send("$ ")
                command = ""
                while not command.endswith("\r"):
                    transport = chan.recv(1024)
                    print(client_ip + ':' + str(client_port) + "- received:", transport)
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
                logger.info('Command receied ({},{}): {}'.format(client_ip, client_port, command))
                # detect_url(command, client_ip)

                if command == "exit" or command == "quit" or command == "logout":
                    end = time.time()
                    duration = end - start
                    date_time = float(start) + 6 * 60 * 60 + float(duration)
                    date_time = time.localtime(date_time)
                    date_time = time.strftime("[%d/%b/%Y %H:%M:%S]", date_tme)

                    logger_2.info(
                        '{} {} {} {} {},{},{},{},{},{},{},{},{},{},{},{},{},{}'.format(
                            str(date_time), str(src_ip), str(src_port), str(dst_ip), str(dst_port), str(hot),
                            str(num_failed_login), str(logged_in), str(num_compromised_file), str(root_shell),
                            str(su_attempted), str(num_root), str(num_file_creations), str(num_shells),
                            str(num_access_files), str(num_outbound_cmds), str(is_hot_login), str(is_guest_login)))

                    run = False



                else:
                    ###############
                    if command == "su root":
                        su_attempted = 1
                        num_root = num_root + 1
                        chan.send("passward:")
                        passward = ""
                        while not passward.endswith("\r"):
                            recivedpass = chan.recv(1024)
                            passward += recivedpass.decode("utf-8")
                        chan.send("\r\n")
                    if command.startswith(">") or command.startswith("touch") or command.startswith(
                            "cat >") or command.startswith("echo"):
                        num_file_creations = num_file_creations + 1
                        if command.startswith(">"):
                            txt = ""
                            txt1 = ""
                            while not txt1.endswith('\x03'):
                                recivedtxt = chan.recv(1024)
                                if recivedtxt.decode("utf-8") == "\r":
                                    txt = "\r\n"
                                else:
                                    txt = recivedtxt.decode("utf-8")
                                chan.send(txt)
                                txt1 += recivedtxt.decode("utf-8")
                    if command.startswith("root"):
                        num_root = num_root + 1

                    handle_cmd(command, chan, client_ip, client_port)

        except Exception as err:
            end = time.time()
            ##########end = now()
            duration = end - start
            date_time = float(start) + 6 * 60 * 60
            date_time = time.localtime(date_time)
            date_time = time.strftime("[%d/%b/%Y %H:%M:%S]", date_time)
            logger.info(
                'connection closed from: {}, port : {} , time: {},protocol_type: {},service_type: {},logged_in:{}, su_attempted:{}, Num_file_creations: {},Root_shell: {}'.format(
                    client_ip, client_port, duration, protocol_type, service_type, str(logged_in), str(su_attempted),
                    str(num_file_creations), str(root_shell)))
            logger_2.info(
                '{} {} {} {} {},{},{},{},{},{},{},{},{},{},{},{},{},{}'.format(
                    str(date_time), str(src_ip), str(src_port), str(dst_ip), str(dst_port), str(hot),
                    str(num_failed_login), str(logged_in), str(num_compromised_file), str(root_shell),
                    str(su_attempted), str(num_root), str(num_file_creations), str(num_shells),
                    str(num_access_files), str(num_outbound_cmds), str(is_hot_login), str(is_guest_login)))

            print('!!! Exception: {}: {}'.format(err.__class__, err))
            try:
                transport.close()
            except Exception:
                pass

        chan.close()

    except Exception as err:  ##he tried the pass 3 times and failed
        print('!!! Exception: {}: {}'.format(err.__class__, err))
        date_time = float(start) + 6 * 60 * 60
        date_time = time.localtime(date_time)
        date_time = time.strftime("[%d/%b/%Y %H:%M:%S]", date_time)
        username = server.a_username
        num_shells = 0
        if (username == "root" or username == "Root"):
            is_hot_login = 1
        num_failed_login = server.num_failed
        logger_2.info(
            '{} {} {} {} {},{},{},{},{},{},{},{},{},{},{},{},{},{} '.format(
                str(date_time), str(src_ip), str(src_port), str(dst_ip), str(dst_port), str(hot),
                str(num_failed_login), str(logged_in), str(num_compromised_file), str(root_shell),
                str(su_attempted), str(num_root), str(num_file_creations), str(num_shells),
                str(num_access_files), str(num_outbound_cmds), str(is_hot_login), str(is_guest_login)))
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
        new_thread = threading.Thread(target=handle_connection, args=(client, addr, port))
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

