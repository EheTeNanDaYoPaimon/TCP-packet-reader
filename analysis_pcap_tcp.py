import dpkt
from dpkt.utils import inet_to_str


fileName = "assignment2.pcap"

f = open(".\\" + fileName, 'rb')
pcap = dpkt.pcap.Reader(f)


#counter for getting the first two info of packet
counter = 0

throughput = -1
start = -1
end = 0
period = 0

# for a valid connection need 3 way handshake, 
# first check for syn then check syn + ack then it should end with ack
# only after this a tcp conncetion is made
step = 0
handshake = [dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK + dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK]

tcp_flows = [] # [[source, destination], [seq...], [ack...], [handshake]], ...
# 0 = source
# 1 = handshake
# 2 = list of seq
# 3 = list of ack

tcp_congestion_windows = [] # [source, destination], [cwnd1, 2, 3], [cwnd, current_seq, expected_ack]

# for display use
tcp_display = [] # [[source, destination], [[seq1, ack1],[seq2,ack2]], [triple dup, timeout], [cwnd 1, 2, 3]]...


for ts, buf in pcap:

	

	counter += 1
	# if counter == 3150:
	# 	break

	eth = dpkt.ethernet.Ethernet(buf)
	ip = eth.data
	tcp = ip.data
	packet = str(tcp.pack_hdr)

	#if it is not tcp then skip to next packet
	if ip.p != dpkt.ip.IP_PROTO_TCP:
		continue
	
	#source and destination IP and PORT
	# srcIP = "source IP : " +  str(inet_to_str(ip.src))
	# srcPort = "source port : " + str(tcp.sport)
	# dstIP = "destination IP : " + str(inet_to_str(ip.dst))
	# dstPort = "destination port : " + str(tcp.dport)

	# src = str(inet_to_str(ip.src)) + ":" + str(tcp.sport)
	# dst = str(inet_to_str(ip.dst)) + ":" + str(tcp.dport)

	# seq = "Sequence number : " + str(tcp.seq)
	# ack = "Ack number : " + str(tcp.ack)
	# win = "Receive Window size : " + str(tcp.win)

	# display the first two transaction after connection is set up
	# include [ACK], [SYN, ACK], [PSH, ACK], [FIN, ACK]
	# if tcp.flags == dpkt.tcp.TH_ACK and (str(src+','+dst) in tcp_flows.keys() or str(dst+','+src) in tcp_flows.keys()) :
	# 	# if counter != 0:
	# 	# 	print(f"{srcIP : <30}{srcPort : <20}{dstIP : <36}{dstPort : <25}{seq : <30}{ack : <25}{win : <1}")
	# 	# 	counter -= 1
	# 	# else:
	# 	# 	print(f"{srcIP : <30}{srcPort : <20}{dstIP : <36}{dstPort : <25}")

	# 	# append the seq and ack to the flow
	# 	info = [seq ,ack, win]
	# 	if str(src+','+dst) in tcp_flows.keys():
	# 		tcp_display[str(src+','+dst)].append(info) 
	# 	if str(dst+','+src) in tcp_flows.keys():
	# 		tcp_display[str(dst+','+src)].append(info) 



	# recognize ack and the src + dst and make a new flow
	path = [inet_to_str(ip.src) +":"+ str(tcp.sport), inet_to_str(ip.dst) +":"+ str(tcp.dport)]

	flow_already_exist = False

	#search for the path and append or delete accordingly
	for flow in tcp_flows:

		triple_duplicate = 0
		timeout = 0

		# get the path in the list of paths
		if set(path) == set(flow[0]):

			flow_already_exist = True

			#check handshake

			# check if connection is established by checking handshake is empty
			if len(flow[3]) > 0:
				#check handshake
				if tcp.flags == flow[3][0]:	
					flow[3].pop(0)
				if len(tcp.data) > 0:
					flow[1].append(tcp.seq)
				break

			#check for triple duplicate first, then check for timeout
			#first check if the seq is less than the already sent ones
			#then check if 3 of the same ack exist or not
			#if there is then triple dup
			#else timeout


			# if the flow is from sender to reciver and the data is not empty
			if path[0] == flow[0][0] and path[1] == flow[0][1] and len(tcp.data) > 0:

				if len(flow[1]) > 1 and tcp.seq < flow[1][-1]:

					# check for potential timeout

					if len(flow[2]) > 1 and flow[2][-1] == flow[2][-1]:
							# if there is three duplicates then change timeout to triple duplicate
							if len(flow[2]) > 2 and flow[2][-1] == flow[2][-3]:
								triple_duplicate += 1
							else:
								timeout += 1
							# print(counter)
							# print(tcp.sport)
							# print(tcp.seq)
							# print(flow[1][-1])
							# print()
				
				else:
					flow[1].append(tcp.seq)

			# if the flow if from reciver to sender
			elif path[1] == flow[0][0] and path[0] == flow[0][1]:
				flow[2].append(tcp.ack)

				flow[1] = list(filter(lambda x: x > flow[2][-1], flow[1]))
			
			cwnd = []

			# estimate the cwnd by setting starting and ending point from seq = seq to where ack = seq + len(tcp.data)
			# we then add all the data length together to get the cwnd from each rtts
			# we can just add without worring about from and to because reciever sends no data meaning the size is zero
			# after we added the datas, we need to delete the offset from the previous window
			#tcp_congestion_windows = [] # [source, destination], [cwnd1, 2, 3], [cwnd, current_seq, expected_ack]

			for window in tcp_congestion_windows:
				if set(window[0]) == set(flow[0]):
					if tcp.ack == window[2][2]:
						offset = sum(window[1])
						window[1].append(window[2][0] - offset)
						window[2][1] = window[2][2] = -1

					if window[2][1] < 0 and len(tcp.data) > 0:
						window[2][1] = tcp.seq # over here, because the seq include all the previous seq we need to remove the offset on line 159
						window[2][2] = tcp.seq + len(tcp.data)

					window[2][0] += len(tcp.data)

					if len(window[1]) > 2:
						cwnd = window[1]

			for d in tcp_display:
				if set(d[0]) == set(flow[0]):
					d[1].append([tcp.seq, tcp.ack, tcp.win])
					d[2][0] += triple_duplicate
					d[2][1] += timeout
					d[3] = cwnd

	if not flow_already_exist:
		tcp_flows.append([path,[],[],[dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK + dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK]])
		tcp_display.append([path, [],[0,0],[]])
		tcp_congestion_windows.append([path, [], [0,-1,-1]])
		#check handshake
		if tcp.flags == tcp_flows[-1][3][0]:
			tcp_flows[len(tcp_flows)-1][3].pop(0)

	#total data 
	throughput += len(tcp.data)

	#getting time
	if(start < 0):
		start = ts
	end = ts
	period += end - start
	start = end

print("throughput : " + str(throughput))
print("period : " + str(period))

for k in tcp_display:
	print()

	srcIP = "source IP : " +  str(k[0][0].split(':')[0])
	srcPort = "source port : " + str(k[0][0].split(':')[1])
	dstIP = "destination IP : " + str(k[0][1].split(':')[0])
	dstPort = "destination port : " + str(k[0][1].split(':')[1])

	print(srcIP)
	print(srcPort)
	print(dstIP)
	print(dstPort)

	seq = "Sequence number : " + str(k[1][0][0])
	ack = "Ack number : " + str(k[1][0][1])
	win = "Receive Window size : " + str(k[1][0][2])

	print(seq +"  "+ ack +"  "+ win)

	
	seq = "Sequence number : " + str(k[1][0][0])
	ack = "Ack number : " + str(k[1][0][1])
	win = "Receive Window size : " + str(k[1][0][2])

	print(seq +"  "+ ack +"  "+ win)

	print( str(k[2][0]) +" triple duplicate ack retransmission(s).")
	print( str(k[2][1]) + " time out retransmission(s).")

	for i in range(0, 3):
		if i == len(k[3]):
			break
		print("Congestion window " + str(i+1) + " is " + str(k[3][i]))
	
	#From the results, the congestion windows are growing somewhat close to exponential. 
	#There is a increase about 13000, 15000, and 19000 after each cwnd.

f.close()
