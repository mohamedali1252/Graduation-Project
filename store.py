import os
import redis
import subprocess
import sys

sys.path.insert(1, '/home/kali/Desktop/all/')
import settings as sm



#list_files = subprocess.run(["ls", "-l"])

    

def send_data(redis_connection):
    count = 0
    while os.path.getsize(sm.FEATURES_PATH) <= 0:
        print('empty conn')

    conn_csv_file = open(sm.FEATURES_PATH, "r")
    for con in conn_csv_file:

        try:
                data = {
                    "feature_v": con,  # feature vector
                }
                resp = redis_connection.xadd('featurevector_stream', data)
                print(resp)
                count += 1

        except ConnectionError as e:
            print("ERROR REDIS CONNECTION: {}".format(e))
            
    ips_file = open(sm.IPS_PATH, "r")
    #print(redis_connection.xdel('ips_stream',0))
    #print('trim')
    #redis_connection.xtrim('ips_stream',minid=0) 
    for line in ips_file:

        try:
                data = {
                    "ips": line,  # feature vector
                }
                resp = redis_connection.xadd('ips_stream', data)
                print(resp)
                count += 1

        except ConnectionError as e:
            print("ERROR REDIS CONNECTION: {}".format(e))


if __name__ == "__main__":
          ip = sys.argv[1]
          r = redis.Redis(
                    host= ip,
                    port=6379)
          if r.ping():
	          print("PONG")	
          else:
                    print("Connection failed!")
          send_data(r)
          print()




