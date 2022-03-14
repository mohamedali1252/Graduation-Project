import sys



def all_the_work():
	connections = []
	connections_after=[]
	connections_count = 0
	if len(sys.argv) != 2:
		return 1
	else:
		read = sys.argv[1]
		file_csv = open(read, "r")
		for x in file_csv:
			connections.append(x)
			connections_count = connections_count + 1
		file_csv.close()
		counter2 = 0
		for counter in range(0,connections_count):
			line1 = connections[counter]
			sep_conn = line1.split(",")
			#print(sep_conn)
			conn_no1 = sep_conn[0]
			duration1s = sep_conn[1]
			orig_p1 = int(sep_conn[2])
			resp_p1 = int(sep_conn[3])
			orig_h1 = sep_conn[4]
			resp_h1 = sep_conn[5]
			duration1 = sep_conn[6]
			protocol1 = sep_conn[7]
			service1 = sep_conn[8]
			flag1 = sep_conn[10]
			du_temp = duration1s.split(".")
			has_duration1 = int(du_temp[0])
			has_duration12 = int(du_temp[1])
			###############################################
			start2=0
			count=0
			serror=0
			rerror=0
			same_srv=0
			diff_srv=0
			srv_count=0
			srv_serror=0
			srv_error=0
			srv_diff_host=0
			j=counter2
			for j in range(0,counter):
				line2 = connections[j]
				sep_conn2 = line2.split(",")
				conn_no2 = sep_conn2[0]
				duration2s = sep_conn2[1]
				orig_p2 = int(sep_conn2[2])
				resp_p2 = int(sep_conn2[3])
				orig_h2 = sep_conn2[4]
				resp_h2 = sep_conn2[5]
				duration2 = sep_conn2[6]
				protocol2 = sep_conn2[7]
				service2 = sep_conn2[8]
				flag2 = sep_conn2[10]
				du_temp2 = duration2s.split(".")
				has_duration2 = int(du_temp2[0])
				has_duration22 = int(du_temp2[1])
				if (has_duration1-2)<=has_duration2 and has_duration2<=has_duration1:
					if start2==0:
						counter2=j
						start2=1
					if resp_h1 == resp_h2:
						count= count + 1
						if flag2=="S0" or flag2 == "S1" or flag2=="S2" or flag2=="S3":
							serror= serror + 1
						if flag2=="REJ":
							rerror= rerror + 1
						if service2 != "other" !=0 and service1 == service2 :
							same_srv= same_srv + 1
						if service1!=service2:
							diff_srv= diff_srv + 1
					if resp_p1==resp_p2:
						srv_count= srv_count + 1
						if flag2 == "S0" or flag2=="S1" or flag2=="S2" or flag2=="S3" :
							srv_serror= srv_serror + 1
						if flag2 =="REJ":
							srv_error= srv_error + 1
						if resp_h1 != resp_h2:
							srv_diff_host= srv_diff_host + 1
			if count != 0:
				serror_rate=float(serror)/float(count)
				rerror_rate=float(rerror)/float(count)
				same_srv_rate=float(same_srv)/float(count)
				diff_srv_rate=float(diff_srv)/float(count)
			else:
				serror_rate= float(0)
				rerror_rate= float(0)
				same_srv_rate= float(0)
				diff_srv_rate= float(0)
			if srv_count!=0:
				srv_serror_rate=float(srv_serror)/float(srv_count)
				srv_error_rate=float(srv_error)/float(srv_count)
				srv_diff_host_rate=float(srv_diff_host)/float(srv_count)
			else:
				srv_serror_rate= float(0)
				srv_error_rate= float(0)
				srv_diff_host_rate= float(0)
			line = line1.rstrip() + ","+str(count)+","+str(srv_count)+","+str(serror_rate)+","+str(srv_serror_rate)+","+str(rerror_rate)+","+str(srv_error_rate)+","+str(same_srv_rate)+","+str(diff_srv_rate)+","+str(srv_diff_host_rate)
			#connections[counter]=line
			#connections_after.append(line) #######################
			if counter<=100:
				counter100=0
			else:
				counter100=counter-100
			count=0
			serror=0
			rerror=0
			same_srv=0
			diff_srv=0
			srv_count=0
			srv_serror=0
			srv_error=0
			srv_diff_host=0
			same_src_port=0
			j = counter100
			for j in range(0,counter):
				line2 = connections[j]
				sep_conn2 = line2.split(",")
				conn_no2 = sep_conn2[0]
				duration2s = sep_conn2[1]
				orig_p2 = int(sep_conn2[2])
				resp_p2 = int(sep_conn2[3])
				orig_h2 = sep_conn2[4]
				resp_h2 = sep_conn2[5]
				duration2 = sep_conn2[6]
				protocol2 = sep_conn2[7]
				service2 = sep_conn2[8]
				flag2 = sep_conn2[10]
				du_temp2 = duration2s.split(".")
				has_duration2 = int(du_temp2[0])
				has_duration22 = int(du_temp2[1])
				if resp_h1==resp_h2:
					count= count + 1
					if flag2=="S0" or flag2=="S1" or flag2=="S2" or flag2 == "S3":
						serror= serror + 1
					if flag2 == "REJ":
						rerror= rerror + 1
					if service2!="other" and service1==service2:
						same_srv= same_srv + 1
					if service1!=service2:
						diff_srv= diff_srv + 1
				if resp_p1==resp_p2:
					srv_count= srv_count + 1
					if flag2=="S0" or flag2=="S1" or flag2=="S2" or flag2=="S3":
						srv_serror= srv_serror + 1
					if flag2=="REJ":
						srv_error= srv_error + 1
					if resp_h1!=resp_h2:
						srv_diff_host= srv_diff_host + 1
				if orig_p1==orig_p2:
					same_src_port= same_src_port + 1
			if count!=0:
				serror_rate=float(serror)/float(count)
				rerror_rate=float(rerror)/float(count)
				same_srv_rate=float(same_srv)/float(count)
				diff_srv_rate=float(diff_srv)/float(count)
			else:
				serror_rate= float(0)
				rerror_rate= float(0)
				same_srv_rate=float(0)
				diff_srv_rate= float(0)
			if srv_count!=0:
				srv_serror_rate=float(srv_serror)/float(srv_count)
				srv_rerror_rate=float(srv_error)/float(srv_count)
				srv_diff_host_rate=float(srv_diff_host)/float(srv_count)
			else:
				srv_serror_rate= float(0)
				srv_rerror_rate= float(0)
				srv_diff_host_rate= float(0)
			if counter-counter100!=0:
				same_src_port_rate=float(same_src_port)/float(counter-counter100)
			else:
				same_src_port_rate=float(0)
			line = line.rstrip() + ","+str(count)+","+str(srv_count)+","+str(same_srv_rate)+","+str(diff_srv_rate)+","+str(same_src_port_rate)+","+str(srv_diff_host_rate)+","+str(serror_rate)+","+str(srv_serror_rate)+","+str(rerror_rate)+","+str(srv_rerror_rate)+"\n"
			connections[counter]=line
			#connections_after.append(line)
			
				
		file_csv = open("dataaa.txt", "w")
		for lines in range(0,connections_count):
			file_csv.write(connections[lines])
		file_csv.close()
	
	
all_the_work()