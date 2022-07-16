import redis
import sys
sys.path.insert(1, '/home/kali/Desktop/all/')
import settings as sm



r = redis.Redis(
                host= 'localhost',
                port=6379
	       )
    
length  = r.xlen('featurevector_stream')  #done
                
print(length)
last_id = 0

con_csv_file = open(sm.FEATURES_DB_PATH, "w")
ips_file = open(sm.CLASS_IPS_PATH,'w')


print('IPs =========================')	
for i in range(10):

	resp = r.xread({'ips_stream': last_id}, count=1)
	if resp:
		
		key, messages = resp[0]
		last_id, data = messages[0]
		#print(resp)
		print('yarab')
		print(data)
		print(data[b'ips'])
		ips_file.write(data[b'ips'].decode("utf-8"))


print('features =========================')	
last_id = 0

for i in range(length):
	print('element no.',i)
	resp = r.xread({'featurevector_stream': last_id}, count=1)
	if resp:
		
		key, messages = resp[0]
		last_id, data = messages[0]
		#print(resp)
		print(data)
		print(data[b'feature_v'])
		#print(type(data)) #dict
		print(type(data[b'feature_v']))
		#print(str(data[b'some_id']))
		#print(last_id)
		#write in csv file 
		con_csv_file.write(data[b'feature_v'].decode("utf-8"))
		
#r.xdel('ips_stream')
		
