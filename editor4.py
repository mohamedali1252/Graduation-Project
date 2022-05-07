import sys
import time
import os
from time import strftime
import datetime
from tablethree_editor4 import table_three


def edit_features():
        connections = []
        connections_after = []
        connections_count = 0
        con_array = []
        line2 = ''
        #for attacks that are not in log files
        ssh_match = 0
        ftp_match = 0
        smtp_match = 0



  
        read = "conn_sort.list"
        file_csv = open(read, "r")
        for x in file_csv:
            connections.append(x)
            con_array.append(x.split())  # table3
            connections_count = connections_count + 1
        file_csv.close()
        for counter in range(0, connections_count):
            line1 = connections[counter]
            line1 = line1.rstrip('/n')
            print('linehgdcfhyfdghcjgdsjhhdkdaJOAE')
            print(line1)
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

            #############
            print('checking con from the conn_sort.list')
            print(line1)
            print('now see match with ssh OR FTP')

            ##############

            if service == "ssh" or resp_p == "22":

                file_ssh = open("ssh.log", "r")
                ssh_match = 0
                for x in file_ssh:
                    print('x in ssh')
                    x = x.split('\n')
                    x = x[0]
                    x = x.rstrip()  #to remove trailer spaces


                    y = x.split(']')
                    s = y[0] + ']'
                    #print(y[0]+']')
                    #print(total)
                    # [date time] src_ip src_port dst_ip dst_port,hot,num_failed_login,logged_in,num_compromised_file,root_shell,su_attempted,num_root,num_file_creations,num_shells,num_access_files,num_outbound_cmds,is_hot_login,is_guest_login
                    if (s == time_string) and (orig_h in x) and (orig_p in x) and (resp_h in x) and (resp_p in x):
                        # print('timestring', time_string)
                        # print(x)
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
                        ssh_match = 1
                        print('is guest login')
                        print(is_guest_login,'hey')
                        print('jjj')
                        print(protocol,'hey')
                        print(line2)
                        break;

                if ssh_match == 0 and service == 'ssh':
                    print('in ssh but in Probes')

                    line2 = duration + "," + protocol + "," + "ssh" + "," + flag + "," + src_bytes + "," + dst_bytes + "," + land + "," + wrong_fragment + "," + urgent + "," + hot + "," + num_failed_logins + "," + logged_in + "," + num_compromised + "," + root_shell + "," + su_attempted + "," + num_root + "," + num_file_creations + "," + num_shells + "," + num_access_files + "," + num_outbound_cmds + "," + is_hot_login + "," + '0'
                    connections_after.append(line2)
                    print('ssh_match = 0')
                    print(sep_conn)

            
            elif service == "ftp" or resp_p == "21":
                print('--------------in ftp----------------------')
                file_ftp = open("ftplog.txt", "r")
                print(time_string)
                ftp_match = 0
                for x in file_ftp:
                    x = x.split('\n')
                    x = x[0]
                    x = x.rstrip()  # to remove trailer spaces
                    print('x from ftp')
                    print(x)
                   

                    y = x.split(']')
                    s = y[0] + ']'
                    print(' from ftplog >> S = ',s)
                    print('from conn_sort>>timestring',time_string)


                    if (s == time_string) and (orig_h in x) and (orig_p in x) and (resp_h in x) and (resp_p in x):
                        print('match with ftplog.txt')
                        print(sep_conn)


                        #print(x)
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
                        ftp_match = 1
                        break;

                if ftp_match == 0 and service == 'ftp':
                    line2 = duration + "," + protocol + "," + "ftp" + "," + flag + "," + src_bytes + "," + dst_bytes + "," + land + "," + wrong_fragment + "," + urgent + "," + hot + "," + num_failed_logins + "," + logged_in + "," + num_compromised + "," + root_shell + "," + su_attempted + "," + num_root + "," + num_file_creations + "," + num_shells + "," + num_access_files + "," + num_outbound_cmds + "," + is_hot_login + "," + '0'
                    connections_after.append(line2)

                    print('ftp But in Probes  ')
                        
                    print(line2)
                    print(x)






        print('before table 33333333333333333333333333333333333333')
        print('yarab ba2a')
        print(connections_after)
        table_three(connections_after, "conn_sort.list", 2)
        file_after = open("formated.txt", "w")
        for i in range(0, len(connections_after)):
            file_after.write(connections_after[i])
        file_after.close()


edit_features()