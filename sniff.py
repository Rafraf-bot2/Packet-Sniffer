import struct
import socket
import textwrap

TAB1 = '\t - '
TAB2 = '\t\t - '
TAB3 = '\t\t\t - '
TAB4 = '\t\t\t\t - '

DATAB1 = '\t '
DATAB2 = '\t\t '
DATAB3 = '\t\t\t '
DATAB4 = '\t\t\t\t '

def main():
	conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

	while True:
		raw_data, adr = conn.recvfrom(65536)
		dest_mac, src_mac, eth_prot, data = eth_frame(raw_data)
		print('\nEthernet Frame:')
		print(TAB1 + 'Destination : {}, Source : {}, Protocol : {}'.format(dest_mac, src_mac, eth_prot))

		#8 = IPv4
		if eth_prot == 8:
			ver , headlen, ttl, prot, src, trg, data = ipv4_packet(data)
			print(TAB1 + 'IPv4 Packet:')
			print(TAB2 + 'Version: {}, Header Length: {}, TTL: {}'.format(ver,headlen,ttl))
			print(TAB2 + 'Protocol: {}, Source: {}, Target: {}'.format(prot,src,trg))

			#ICMP
			if prot == 1:
				icmp_type, code, checksum, data = icmp_packet(data)
				print(TAB1 + 'ICMP Packet:')
				print(TAB2 + 'Type {}, Code: {}, Checsum: {},'.format(icmp_type,code,checksum))
				print(format_mult_line(DATAB3,data))

			#TCP
			elif prot == 6:
				src_port, dest_port, seq, ack, flg_urg, flg_ack, flg_psh, flg_rst, flg_syn, flg_fin, data = tcp_segment(data)
				print(TAB1 + 'TCP Segment:')
				print(TAB2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
				print(TAB2 + 'Sequence: {}, Acknowlodgment: {}'.format(seq, ack))
				print(TAB2 + 'Flags:')
				print(TAB3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flg_urg, flg_ack, flg_psh, flg_rst, flg_syn, flg_fin))
				print(TAB2 + 'Data:')
				print(format_mult_line(DATAB3, data))

			#UDP
			elif prot == 17:
				src_port, dest_port, size, data = udp_segment(data)
				print(TAB1 + 'UDP Segment:')
				print(TAB2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port,dest_port,size))
				print(TAB2 + 'Data:')
				print(format_mult_line(DATAB3, data))

			#Autre	
			else:
				print(TAB1 + 'Data:')
				print(format_mult_line(DATAB2, data))
		else:
			print('Data:')
			print(format_mult_line(DATAB1, data))


#unpack trame ethernet
def eth_frame(data):
	dest_mac, src_mac, prot = struct.unpack('! 6s 6s H',data[:14])
	return get_mac_adr(dest_mac), get_mac_adr(src_mac), socket.htons(prot), data[14:]


#formatage @mac (AA:BB:CC:DD:EE:FF) 
def get_mac_adr(bytes_adr):
	bytes_str = map('{:02x}'.format, bytes_adr)
	return ':'.join(bytes_str).upper()

#unpack paquets IPv4
def ipv4_packet(data):
	ver_headlen = data[0]
	ver = ver_headlen >> 4
	headlen = (ver_headlen & 15) * 4
	ttl, prot, src, trg = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
	return ver , headlen, ttl, prot, ipv4(src), ipv4(trg), data[headlen:]

#formatage @ipv4 (127.0.0.1)
def ipv4(adr):
	return '.'.join(map(str, adr))

#unpack paquet icmp
def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[4:]

#unpack segment tcp
def tcp_segment(data):
	src_port, dest_port, seq, ack, off_res_flg = struct.unpack('! H H L L H', data[:14])
	off = (off_res_flg >> 12) * 4
	flg_urg = (off_res_flg & 32) >> 5
	flg_ack = (off_res_flg & 16) >> 4
	flg_psh = (off_res_flg & 8) >> 3
	flg_rst = (off_res_flg & 4) >> 2
	flg_syn = (off_res_flg & 2) >> 1
	flg_fin = off_res_flg & 1
	return src_port, dest_port, seq, ack, flg_urg, flg_ack, flg_psh, flg_rst, flg_syn, flg_fin, data[off:]

#unpack segment udp
def udp_segment(data):
	src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
	return src_port, dest_port, size, data[:8]

#formatage data sur plusieurs lignes
def format_mult_line(pref, string, size=80):
	size -= len(pref)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([pref + line for line in textwrap.wrap(string, size)])


main()