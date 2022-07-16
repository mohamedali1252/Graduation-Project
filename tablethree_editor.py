import sys
import time
import os
from time import strftime
import datetime

test_yarab = ''

def time_insec(epoch_time):
    t = time.localtime(epoch_time)
    con_srtime = int(t.tm_sec) + float(t.tm_min) * 60
    return con_srtime


def table_three(connections_after,filename, mode):
    Count = []
    Srv_count = []
    Serror_rate = []
    Srv_serror_rate = []
    Rerror_rate = []
    Srv_rerror_rate = []
    Same_srv_rate = []
    Diff_srv_rate = []
    Srv_diff_host_rate = []
    Dst_host_count = []
    Dst_host_srv_count = []
    Dst_host_same_srv_rate = []
    Dst_host_diff_srv_rate = []
    Dst_host_same_src_port_rate = []
    Dst_host_srv_diff_host_rate = []
    Dst_host_serror_rate = []
    Dst_host_srv_serror_rate = []
    Dst_host_rerror_rate = []
    Dst_host_srv_rerror_rate = []

    # raed file to add table 3 Features
    con_array = []
    connections_count = 0
    file_name = open(filename, "r")
    for x in file_name:
        con_array.append(x.split(','))
        connections_count += 1
    file_name.close()

    for index, con in enumerate(con_array):


        temp_count = 0
        temp_srv_count = 0
        temp_Serror_rate = 0
        temp_srv_Serror_rate = 0
        temp_Rerror_rate = 0
        temp_Srv_rerror_rate = 0
        temp_Srv_diff_host_rate = 0
        temp_same_srv_rate = 0
        temp_diff_host_rate = 0

        # starting from 32
        temp_Dst_host_count = 0
        temp_Dst_host_srv_count = 0
        temp_Dst_host_same_srv_rate = 0
        temp_Dst_host_diff_srv_rate = 0
        temp_Dst_host_same_src_port_rate = 0
        temp_Dst_host_srv_diff_host_rate = 0
        temp_Dst_host_serror_rate = 0
        temp_Dst_host_srv_serror_rate = 0
        temp_Dst_host_rerror_rate = 0
        temp_Dst_host_srv_rerror_rate = 0

        window_count = 0

        for con2 in con_array:

            #2 sec time window
            if ((time_insec(float(con[1])) - time_insec(float(con2[1]))) <= 2.0) & (
                    (time_insec(float(con[1])) - time_insec(float(con2[1]))) >= 0):


                #count: if same src (not sure) & same dst  
                if ((con[4] == con2[4]) & (con[5] == con2[5])):

                    #23_count
                    temp_count += 1
                    # 25_Serror_rate : if the connection_flag is one of (SO,S1,S2,S3)
                    if con2[10] in ('S0', 'S1', 'S2', 'S3'):
                        temp_Serror_rate += 1
                    # 27_Rerror_rate: if con_flag is rej
                    if con2[10] == 'REJ':
                        temp_Rerror_rate += 1
                    # 29_same_srv_rate : if both connections have the same service
                    if con[3] == con2[3]:
                        temp_same_srv_rate += 1

                    #24_srv_count: if same src &  same dst port 
                if ((con[4] == con2[4]) & (con[3] == con2[3])):
                    temp_srv_count += 1
                    #all the coming features are calculated w.r.t the Srv_Count feature:
                    # 26_srv_Serror_rate: number of cons having the same flag (s0,s1,s2,s3) under the Srv_count feature
                    if con2[10] in ('S0', 'S1', 'S2', 'S3'):
                        temp_srv_Serror_rate += 1
                    # 28_srv_Rerror_rate:
                    if con2[10] == 'REJ':
                        temp_Srv_rerror_rate += 1

                    # 31_Srv_diff_host_rate: if both connections do not have the same service
                    if con[5] != con2[5]: 
                        temp_Srv_diff_host_rate += 1

        if mode == 1:
            # 100 connction window
            window_count = 0

            # loop over con[0]-1 till 100 conn before
            start_idx = con[0]
            for con2 in reversed(con_array[:start_idx]):
                if con2[5] == con[5]:  # consider checking against range of dst IPs later
                    window_count += 1
                    if window_count <= 100:
                        pass
                    else:
                        if con2[4] == con[4]:  # same src
                            temp_Dst_host_count += 1
                            if con2[3] == con[3]:  # 34
                                temp_Dst_host_same_srv_rate += 1
                            if con2[10] in ('S0', 'S1', 'S2', 'S3'):  # 38
                                temp_Dst_host_serror_rate += 1
                            if con2[10] == 'REJ':  # 40
                                temp_Dst_host_rerror_rate += 1

                        if con2[3] == con[3]:  # 33
                            temp_Dst_host_srv_count += 1
                            if con2[2] == con[2]:  # 36
                                temp_Dst_host_same_src_port_rate += 1
                            if con[5] != con2[5]:  # 37
                                temp_Dst_host_srv_diff_host_rate += 1
                            if con2[10] in ('S0', 'S1', 'S2', 'S3'):  # 39
                                temp_Dst_host_srv_serror_rate += 1
                            if con2[10] == 'REJ':  # 41
                                temp_Dst_host_srv_rerror_rate += 1
        elif mode == 2:
            # take a window of 2 min based on avg time of probing
            for con2 in con_array:
                if ((time_insec(float(con[1])) - time_insec(float(con2[1]))) <= 120.0) & (
                        (time_insec(float(con[1])) - time_insec(float(con2[1]))) >= 0):

                    if con2[5] == con[5]:  # same dst IP
                        #32_ Number of connections having the same destination host IP address
                        temp_Dst_host_count += 1


                        #34_% of cons that were to the same service, among the connections aggregated in dst_host_count (32)
                        if con2[3] == con[3]:  # 34
                            temp_Dst_host_same_srv_rate += 1
                        #38_% of cons that have activated the flag (4) s0, s1, s2 or s3, among the connections aggregated in dst_host_count (32)
                        if con2[10] in ('S0', 'S1', 'S2', 'S3'):  # 38
                            temp_Dst_host_serror_rate += 1
                        #40_% of consthat have activated the flag (4) REJ, among the connections aggregated in dst_host_count (32)
                        if con2[10] == 'REJ':  # 40
                            temp_Dst_host_rerror_rate += 1

                    if con2[3] == con[3]:  # 33 same dst port only
                        #33_Number of connections having the same destination port only
                        temp_Dst_host_srv_count += 1
                        #36_% of cons that were to the same source port, among the connections aggregated in dst_host_srv_count(33)
                        if con2[2] == con[2]:  # 36
                            temp_Dst_host_same_src_port_rate += 1
                        #37_% of cons that were to different destination machines, among the connections aggregated in dst_host_srv_count (33)
                        if con[5] != con2[5]:  # 37
                            temp_Dst_host_srv_diff_host_rate += 1
                        #39_% of cons that have activated the flag (4) s0, s1, s2 or s3, among the connections aggregated in dst_host_srv_c ount (33)
                        if con2[10] in ('S0', 'S1', 'S2', 'S3'):  # 39
                            temp_Dst_host_srv_serror_rate += 1
                        #41_% of cons that have activated the flag (4) REJ, among the connections aggregated in dst_host_srv_c ount (33)
                        if con2[10] == 'REJ':  # 41
                            temp_Dst_host_srv_rerror_rate += 1

        Count.append(temp_count)
        if temp_count != 0:
            Serror_rate.append(round((float(temp_Serror_rate) / temp_count), 2))
            Rerror_rate.append(round((float(temp_Rerror_rate) / temp_count), 2))
            # 29
            Same_srv_rate.append(round((float(temp_same_srv_rate) / temp_count), 2))
            # 30
            Diff_srv_rate.append(round((1 - (float(temp_same_srv_rate) / temp_count)), 2))
        else:
            Serror_rate.append(float(0))
            Same_srv_rate.append(float(0))
            Rerror_rate.append(float(0))
            Diff_srv_rate.append(float(0))

        Srv_count.append(temp_srv_count)
        if temp_srv_count != 0:
            Srv_serror_rate.append(round((float(temp_Serror_rate) / temp_srv_count), 2))
            Srv_rerror_rate.append(round((float(temp_Rerror_rate) / temp_srv_count), 2))
            Srv_diff_host_rate.append(round((float(temp_Srv_diff_host_rate) / temp_srv_count), 2))
        else:
            Srv_serror_rate.append(float(0))
            Srv_rerror_rate.append(float(0))
            Srv_diff_host_rate.append(float(0))
        # 32

        Dst_host_count.append(temp_Dst_host_count)
        if temp_Dst_host_count != 0:
            Dst_host_same_srv_rate.append(round((float(temp_Dst_host_same_srv_rate) / temp_Dst_host_count), 2))
            Dst_host_diff_srv_rate.append(round((1 - (float(temp_Dst_host_same_srv_rate) / temp_Dst_host_count)), 2))
            Dst_host_rerror_rate.append(round((float(temp_Dst_host_rerror_rate) / temp_Dst_host_count), 2))
            Dst_host_serror_rate.append(round((float(temp_Dst_host_serror_rate) / temp_Dst_host_count), 2))
        else:
            Dst_host_same_srv_rate.append(float(0))
            Dst_host_diff_srv_rate.append(float(0))
            Dst_host_rerror_rate.append(float(0))
            Dst_host_serror_rate.append(float(0))

        # 33
        Dst_host_srv_count.append(temp_Dst_host_srv_count)
        if temp_Dst_host_srv_count != 0:

            Dst_host_same_src_port_rate.append(round((float(temp_Dst_host_same_src_port_rate) / temp_Dst_host_srv_count), 2))
            Dst_host_srv_diff_host_rate.append(round(float(temp_Dst_host_srv_diff_host_rate) / temp_Dst_host_srv_count, 2))
            Dst_host_srv_rerror_rate.append(round(float(temp_Dst_host_srv_rerror_rate) / temp_Dst_host_srv_count, 2))
            Dst_host_srv_serror_rate.append(round(float(temp_Dst_host_srv_serror_rate) / temp_Dst_host_srv_count, 2))
        else:
            Dst_host_same_src_port_rate.append(float(0))
            Dst_host_srv_diff_host_rate.append(float(0))
            Dst_host_srv_rerror_rate.append(float(0))
            Dst_host_srv_serror_rate.append(float(0))

    # append to the file



    for index, i in enumerate(connections_after):
        temp = str(Count[index]) + "," + str(Srv_count[index]) + "," + str(Serror_rate[index]) + "," + str(
            Srv_serror_rate[index]) + "," + str(Rerror_rate[index]) + "," + str(Srv_rerror_rate[index]) + "," + str(
            Same_srv_rate[index]) + "," + str(Diff_srv_rate[index]) + "," + str(Srv_diff_host_rate[index]) + "," + str(
            Dst_host_count[index]) + "," + str(Dst_host_srv_count[index]) + "," + str(
            Dst_host_same_srv_rate[index]) + "," + str(Dst_host_diff_srv_rate[index]) + "," + str(
            Dst_host_same_src_port_rate[index]) + "," + str(Dst_host_srv_diff_host_rate[index]) + "," + str(
            Dst_host_serror_rate[index]) + "," + str(Dst_host_srv_serror_rate[index]) + "," + str(
            Dst_host_rerror_rate[index]) + "," + str(Dst_host_srv_rerror_rate[index])
        connections_after[index] += ','+temp + '\n'
        temp = ''
