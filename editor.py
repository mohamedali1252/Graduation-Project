import sys
import time
import os
from time import strftime
import datetime
from tablethree_editor import table_three

sys.path.insert(1, '/home/kali/Desktop/all/')
import settings as sm


def edit_features():
        connections = []
        connections_after = []
        ips_list = []
        connections_count = 0
        con_array = []
        line2 = ''
        #for attacks that are not in log files
        ssh_match = 0
        ftp_match = 0
        smtp_match = 0



  
        read = sm.CONN_SORT_PATH
        file_csv = open(read, "r")
        for x in file_csv:
            connections.append(x)
            con_array.append(x.split())  # table3
            connections_count = connections_count + 1
        file_csv.close()
        for counter in range(0, connections_count):
            line1 = connections[counter]
            line1 = line1.rstrip('/n')
            sep_conn = line1.split(",")
            conn_no = sep_conn[0]
            start_time = sep_conn[1]
            orig_p = sep_conn[2]
            resp_p = sep_conn[3]
            orig_h = sep_conn[4]
            resp_h = sep_conn[5]
            duration = sep_conn[6]
            protocol = sep_conn[7]
            service = sep_conn[8]
            unknown = sep_conn[9]
            flag = sep_conn[10]
            src_bytes = sep_conn[11]
            dst_bytes = sep_conn[12]
            land = sep_conn[13]
            wrong_fragment = sep_conn[14]
            urgent = sep_conn[15]
            total = float(start_time) + 6 * 60 * 60
            t = time.localtime(total)
            time_string = time.strftime("[%d/%b/%Y %H:%M:%S]", t)
            hot = sep_conn[16]
            num_failed_logins = sep_conn[17]
            logged_in = sep_conn[18]
            num_compromised = sep_conn[19]
            root_shell = sep_conn[20]
            su_attempted = sep_conn[21]
            num_root = sep_conn[22]
            num_file_creations = sep_conn[23]
            num_shells = sep_conn[24]
            num_access_files = sep_conn[25]
            num_outbound_cmds = sep_conn[26]
            is_hot_login = sep_conn[27]
            is_guest_login = sep_conn[28]
            line2 = ''
            total2 = float(start_time) + 12 * 60 * 60
            t2 = time.localtime(total2)
            time_string1 = time.strftime("[%d/%b/%Y %H:%M:%S]", t2)
            time_string_temp = time.strftime("%d/%b/%Y,%H:%M:%S", t2)
            time_string_temp2 = time_string_temp.split(',')
            date = time_string_temp2[0]
            ti = time_string_temp2[1]


            ##############

            if service == "ssh" or resp_p == "22":

                file_ssh = open(sm.SSH_LOG_PATH, "r")
                ssh_match = 0
                for x in file_ssh:
                    x = x.split('\n')
                    x = x[0]
                    x = x.rstrip()  #to remove trailer spaces

                    y = x.split(']')
                    s = y[0] + ']'

                    if (s == time_string1) and (orig_h in x) and (orig_p in x) and (resp_h in x) and (resp_p in x):
                    
                        ssh = x.split(",")
                        hot = ssh[1]
                        num_failed_logins = ssh[2]
                        logged_in = ssh[3]
                        num_compromised = ssh[4]
                        root_shell = ssh[5]
                        su_attempted = ssh[6]
                        num_root = ssh[7]
                        num_file_creations = ssh[8]
                        num_shells = ssh[9]
                        num_access_files = ssh[10]
                        num_outbound_cmds = ssh[11]
                        is_hot_login = ssh[12]
                        is_guest_login = ssh[13]
                        line2 = duration + "," + protocol + "," + "ssh" + "," + flag + "," + src_bytes + "," + dst_bytes + "," + land + "," + wrong_fragment + "," + urgent + "," + hot + "," + num_failed_logins + "," + logged_in + "," + num_compromised + "," + root_shell + "," + su_attempted + "," + num_root + "," + num_file_creations + "," + num_shells + "," + num_access_files + "," + num_outbound_cmds + "," + is_hot_login + "," + '0'
                        connections_after.append(line2)
                        ips_list.append(orig_h + ',' + resp_h+',' +date  + ',' + ti + ",ssh\n")
                        ssh_match = 1
                        break;

                if ssh_match == 0 and service == 'ssh':
                    line2 = duration + "," + protocol + "," + "ssh" + "," + flag + "," + src_bytes + "," + dst_bytes + "," + land + "," + wrong_fragment + "," + urgent + "," + hot + "," + num_failed_logins + "," + logged_in + "," + num_compromised + "," + root_shell + "," + su_attempted + "," + num_root + "," + num_file_creations + "," + num_shells + "," + num_access_files + "," + num_outbound_cmds + "," + is_hot_login + "," + '0'
                    connections_after.append(line2)
                    ips_list.append(orig_h + ',' + resp_h+',' +date  + ',' + ti + ",ssh\n")
            
            elif service == "smtp" or resp_p == "25":
                     line2 = duration + "," + protocol + "," + "smtp" + "," + flag + "," + src_bytes + "," + dst_bytes + "," + land + "," + wrong_fragment + "," + urgent + "," + "0" + "," +"0"+ "," +"0"+ "," +"0"+ "," +"0"+ "," + "0"+ "," +"0"+ "," +"0"+ "," +"0"+ "," +"0"+ "," +"0"+ "," +"0"+ "," + '0'
                     connections_after.append(line2)
                     ips_list.append(orig_h + ',' + resp_h+',' +date  + ',' + ti + ",smtp\n")
            elif service == "ftp" or resp_p == "21":
                file_ftp = open(sm.FTP_LOG_PATH, "r")
                ftp_match = 0
                for x in file_ftp:
                    x = x.split('\n')
                    x = x[0]
                    x = x.rstrip()  # to remove trailer spaces
                   

                    y = x.split(']')
                    s = y[0] + ']'


                    if (s == time_string) and (orig_h in x) and (orig_p in x) and (resp_h in x) and (resp_p in x):
                        ftp = x.split(",")
                        hot = ftp[1]
                        num_failed_logins = ftp[2]
                        logged_in = ftp[3]
                        num_compromised = ftp[4]
                        root_shell = ftp[5]
                        su_attempted = ftp[6]
                        num_root = ftp[7]
                        num_file_creations = ftp[8]
                        num_shells = ftp[9]
                        num_access_files = ftp[10]
                        num_outbound_cmds = ftp[11]
                        is_hot_login = ftp[12]
                        is_guest_login = ftp[13]
                        line2 = duration + "," + protocol + "," + "ftp" + "," + flag + "," + src_bytes + "," + dst_bytes + "," + land + "," + wrong_fragment + "," + urgent + "," + hot + "," + num_failed_logins + "," + logged_in + "," + num_compromised + "," + root_shell + "," + su_attempted + "," + num_root + "," + num_file_creations + "," + num_shells + "," + num_access_files + "," + num_outbound_cmds + "," + is_hot_login + "," + '0'
                        connections_after.append(line2)
                        ips_list.append(orig_h + ',' + resp_h+',' +date  + ',' + ti + ",ftp\n")
                        ftp_match = 1
                        break;

                if ftp_match == 0 and service == 'ftp':
                    line2 = duration + "," + protocol + "," + "ftp" + "," + flag + "," + src_bytes + "," + dst_bytes + "," + land + "," + wrong_fragment + "," + urgent + "," + hot + "," + num_failed_logins + "," + logged_in + "," + num_compromised + "," + root_shell + "," + su_attempted + "," + num_root + "," + num_file_creations + "," + num_shells + "," + num_access_files + "," + num_outbound_cmds + "," + is_hot_login + "," + '0'
                    connections_after.append(line2)
                    ips_list.append(orig_h + ',' + resp_h+',' + date  + ',' + ti + ",ftp\n")

        #write in the IPs file
        ips_file = open(sm.IPS_PATH,'w')
        for i in range(0, len(ips_list)):
            ips_file.write(ips_list[i])
        ips_file.close()
        table_three(connections_after, sm.CONN_SORT_PATH, 2)
        file_after = open(sm.FEATURES_PATH, "w")
        for i in range(0, len(connections_after)):
            file_after.write(connections_after[i])
        file_after.close()


edit_features()