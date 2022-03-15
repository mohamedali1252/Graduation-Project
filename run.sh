zeek -r test.pcap darpa2gurekddcup.zeek -C > conn.list &&

sort -n conn.list > conn_sort.list &&

python3 script.py &&

rm conn.list conn.log conn_sort.list dhcp.log dns.log packet_filter.log ssh.log


