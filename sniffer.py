import scapy.all as scapy






#TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
#pkts = scapy.rdpcap('yarab.pcap')
src_ip = ''
dst_ip = ''
src_port = ''
dst_port = ''


connection_id = {} #src_ip, dst







def fun(p):

    #check for connection establishment SYN = 1 and ACK = 0
        src_ip   =   p[scapy.IP].src 
        dst_ip   =   p[scapy.IP].dst
        src_port =   p[scapy.IP].sport
        dst_port =   p[scapy.IP].dport
       
        if SYN & p['TCP'].flags and (ACK & p['TCP'].flags) == 0:
          print('yes syn flag connection strated')
        
          print(src_ip,':',src_port,dst_ip,':',dst_port)
          #add it to the connection_id dictionary
          id = str(src_ip) + ':'+ str(src_port)
          connection_id[id] = [src_ip,src_port,dst_ip,dst_port,0,0]#'ip:port':[src_ip,src_port,dst_ip,dst_port,src_bytes,dst_bytes]
                                                                   #src_ip always = attacker ip
                                                                   #since he is the one who always initiates a connection

          print(connection_id)
          #check for connection release
        elif FIN & p[scapy.TCP].flags  and  p[scapy.IP].src != b'192.168.56.1' and p[scapy.IP].sport != 22 :
            print('close connection')
            print (p['TCP'].flags)
            print(src_ip,':',src_port,'->',dst_ip,':',dst_port)
            id = str(src_ip) + ':' + str(src_port)
            print('src_bytes=',connection_id[id][4])
            print('dst_bytes=',connection_id[id][5])
           
        else:
         #cal src_Bytes
         
          if p[scapy.IP].src == b'192.168.56.1' and p[scapy.IP].sport == 22 :
              print('da5al')
              id  = str(dst_ip) + ':' + str(dst_port)
              connection_id[id][4] += len(p['TCP'].payload)
              #print(connection_id[id][4])
          elif p[scapy.IP].dst == '192.168.56.1' and p[scapy.IP].dport == 22 :
          #cal dst bytes
              id = str(src_ip) + ':' + str(src_port)
              connection_id[id][5] += len(p['TCP'].payload)
              print('dst',id,'---',dst_ip,dst_port)
        
       

scapy.sniff(offline='yarab.pcap',prn=fun)   
