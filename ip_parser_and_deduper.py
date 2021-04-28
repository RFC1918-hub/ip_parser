#!/usr/bin/python3 

import re
import socket
import struct
import ipaddress
import argparse
from ipparser import ipparser
from socket import inet_aton

def parse_ip(input_ip):
	ip_arr = []
	none_ip_s = []
	ip_s = input_ip.split(",")
	for ip in ip_s:
		## verify ip is correct
		try: 
			check_ip(ip)
			ip_arr += ipparser(ip,resolve=False)
		except:
			try:
				check_network(ip)
				ip_arr += ipparser(ip,resolve=False)
			except:
				try:
					ip_rex = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip) 
					if len(ip_rex) == 2: 
						try:
							ip_arr += findIPs(ip_rex[0], ip_rex[1])
							print("Valid Range: " + ip)
						except:
							print("Not a valid range: " + ip)
							break
					else:
						raise
				except:
					try:
						ip_rex = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}", ip)
						if len(ip_rex) > 0: 
							ip_arr += ipparser(ip,resolve=False)
							print("Valid Short Range: " + ip)
						else:
							raise
					except:
						print("Not valid: " + ip)
						none_ip_s.append(ip)

		
	ip_str = ','.join(ip_arr)
	try:
		ip_return = ipparser(ip_str,resolve=False)
	except:
		print("Something went wrong :(")

	## Sorting list of IP's 
	sorted_ip_return = sorted(ip_return, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0])
	with open("output_ips.txt", 'w') as out_file:
		for line in sorted_ip_return:
			out_file.write("{}\n".format(line))
		out_file.write("\nThe following are not valid IP address or ranges: \n")
		for line in none_ip_s:
			out_file.write("{}\n".format(line))
		out_file.write("\nIP count: {}".format(len(sorted_ip_return)))
		out_file.write("\nOther count: {}".format(len(none_ip_s)))
		print("Output writen to output_ips.txt")

def parse_file(file):
	ip_arr = []
	with open(file, 'r') as read_file:
		for line in read_file:
			ip_arr.append(line.strip())
	ip_str = ','.join(ip_arr)
	parse_ip(ip_str)

def check_ip(input_ip):
	ipaddress.ip_address(input_ip)
	print("Valid IP: " + input_ip)

def check_network(input_ip):
	ipaddress.ip_network(input_ip)
	print("Valid Network: " + input_ip)

def findIPs(start, end):
    ipstruct = struct.Struct('>I')
    start, = ipstruct.unpack(socket.inet_aton(start))
    end, = ipstruct.unpack(socket.inet_aton(end))
    return [socket.inet_ntoa(ipstruct.pack(i)) for i in range(start, end+1)]

def cmdline_args():
	parser = argparse.ArgumentParser(description='IP Parser and Dedup')
	parser.add_argument('-f','--file', help='File to use. IP\'s seperated by new line', required=False)
	parser.add_argument('-i','--ip', help='Comma seperated IP\'s, CIDR or IP range', required=False)

	return(parser.parse_args())

if __name__ == '__main__':

	try:
		args = cmdline_args()
		if args.file: 
			parse_file(args.file)
		if args.ip:
			parse_ip(args.ip)
	except Exception as e:
		print(e)
