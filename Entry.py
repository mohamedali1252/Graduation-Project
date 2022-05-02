

def edit_entry():
    hfile = open("conn_sort.list", "r")
    connections = []
    for line in hfile:
        if ("ssh" in line) or ("ftp" in line) or ("smtp" in line):
            connections.append(line.strip())
    hfile.close()
    attacks = []
    afile = open("attacks.txt", "r")
    for line in afile:
        attacks.append(line.strip())
    afile.close()
    if len(attacks) == len(connections):
        final_file = open("final_file.txt", "w")
        for i in range(len(connections)):
            lar = connections[i].split(',')
            src_ip = lar[4]
            dst_ip = lar[5]
            li = src_ip + " "+dst_ip + " " + attacks[i] +'\n'
            final_file.write(li)
        final_file.close()


edit_entry()
