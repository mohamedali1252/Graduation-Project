import numpy as np
import pandas as pd
from tensorflow import keras
import sys
import os


def classify (inputfilepath):
    col_names = ["duration", "protocol_type", "service", "flag", "src_bytes",
                 "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
                 "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
                 "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
                 "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
                 "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
                 "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
                 "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
                 "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
                 "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]

    dftrying = pd.read_csv(inputfilepath, header=None, names=col_names)

    norm_cols = ['duration', 'src_bytes', 'dst_bytes', 'hot', 'num_compromised', 'num_root', 'num_file_creations',
                 'count', 'srv_count', 'dst_host_count', 'dst_host_srv_count']

    for col in norm_cols:
        dftrying[col] = np.log(dftrying[col] + 1e-6)

    protocol_dummies = pd.get_dummies(dftrying['protocol_type'], prefix='protocol_type')
    service_dummies = pd.get_dummies(dftrying['service'], prefix='service')
    flag_dummies = pd.get_dummies(dftrying['flag'], prefix='flag')
    dftrying = pd.concat([dftrying, protocol_dummies, service_dummies, flag_dummies], axis=1)
    drop_cols = ['protocol_type', 'service', 'flag']
    dftrying.drop(drop_cols, axis=1, inplace=True)

    xshape = ['duration',
              'src_bytes',
              'dst_bytes',
              'land',
              'wrong_fragment',
              'urgent',
              'hot',
              'num_failed_logins',
              'logged_in',
              'num_compromised',
              'root_shell',
              'su_attempted',
              'num_root',
              'num_file_creations',
              'num_shells',
              'num_access_files',
              'num_outbound_cmds',
              'is_host_login',
              'is_guest_login',
              'count',
              'srv_count',
              'serror_rate',
              'srv_serror_rate',
              'rerror_rate',
              'srv_rerror_rate',
              'same_srv_rate',
              'diff_srv_rate',
              'srv_diff_host_rate',
              'dst_host_count',
              'dst_host_srv_count',
              'dst_host_same_srv_rate',
              'dst_host_diff_srv_rate',
              'dst_host_same_src_port_rate',
              'dst_host_srv_diff_host_rate',
              'dst_host_serror_rate',
              'dst_host_srv_serror_rate',
              'dst_host_rerror_rate',
              'dst_host_srv_rerror_rate',
              'protocol_type_icmp',
              'protocol_type_tcp',
              'protocol_type_udp',
              'service_IRC',
              'service_X11',
              'service_Z39_50',
              'service_aol',
              'service_auth',
              'service_bgp',
              'service_courier',
              'service_csnet_ns',
              'service_ctf',
              'service_daytime',
              'service_discard',
              'service_domain',
              'service_domain_u',
              'service_echo',
              'service_eco_i',
              'service_ecr_i',
              'service_efs',
              'service_exec',
              'service_finger',
              'service_ftp',
              'service_ftp_data',
              'service_gopher',
              'service_harvest',
              'service_hostnames',
              'service_http',
              'service_http_2784',
              'service_http_443',
              'service_http_8001',
              'service_imap4',
              'service_iso_tsap',
              'service_klogin',
              'service_kshell',
              'service_ldap',
              'service_link',
              'service_login',
              'service_mtp',
              'service_name',
              'service_netbios_dgm',
              'service_netbios_ns',
              'service_netbios_ssn',
              'service_netstat',
              'service_nnsp',
              'service_nntp',
              'service_ntp_u',
              'service_other',
              'service_pm_dump',
              'service_pop_2',
              'service_pop_3',
              'service_printer',
              'service_private',
              'service_red_i',
              'service_remote_job',
              'service_rje',
              'service_shell',
              'service_smtp',
              'service_sql_net',
              'service_ssh',
              'service_sunrpc',
              'service_supdup',
              'service_systat',
              'service_telnet',
              'service_tim_i',
              'service_time',
              'service_urh_i',
              'service_urp_i',
              'service_uucp',
              'service_uucp_path',
              'service_vmnet',
              'service_whois',
              'flag_OTH',
              'flag_REJ',
              'flag_RSTO',
              'flag_RSTOS0',
              'flag_RSTR',
              'flag_S0',
              'flag_S1',
              'flag_S2',
              'flag_S3',
              'flag_SF',
              'flag_SH']
    xcolshape = pd.DataFrame(columns=xshape)
    fin = pd.concat([xcolshape, dftrying], axis=0, ignore_index=True)
    fin.fillna(0, inplace=True)

    labels = ['back', 'ipsweep', 'neptune', 'nmap', 'normal', 'other',
              'portsweep', 'satan', 'smurf', 'teardrop', 'warezclient']

    model = keras.models.load_model('/home/kali/Desktop/HoneyPot-Neural-network-classifier/my_model.h5')
    pred = model.predict(fin)
    result = np.argmax(pred, axis=1)
    f = open("/home/kali/Desktop/HoneyPot-Neural-network-classifier/ips.txt", "r")
    to_monitor = open("/home/kali/Desktop/ML/test.csv", "w")
    lines = f.readlines()
    
    #f = open("/home/kali/Desktop/ML/test.csv")
    
    i=0
    for r in result :
    	line = lines[i].rstrip('\n')
    	line_after = line.split(',')
    	ay7aga = line_after[0] + "," +  line_after[1] + "," + labels[r] +"," + line_after[2] + "," +line_after[3] + "," +line_after[4] 
    	to_monitor.write(ay7aga +'\n')
    	print(ay7aga)
    	i=i+1

#os.system('python /home/kali/Desktop/HoneyPot-Neural-network-classifier/readfrom_db.py')
file_size=os.path.getsize('/home/kali/Desktop/HoneyPot-Neural-network-classifier/dika.csv') 
if file_size != 0: 
	classify('/home/kali/Desktop/HoneyPot-Neural-network-classifier/dika.csv')
#os.system('redis-cli flushdb')
