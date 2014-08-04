#!/bin/python
# -- coding: utf-8 -- 
#
#mallory2cap.py
#V0.1 31/07/14
#Antonio Cassidy
#antonio.cassidy@pentestpartners.com
#Warning: There may be bugs in yonder code yarrrrrrrr
#
import socket
import struct
import sys
import binascii
import sqlite3 as lite
import sys
import re
import codecs

def main():
	#initialise pcap
	writeheader()
	#read the database
	con = None
	port = 123
	con = lite.connect(sys.argv[1])
	with con:
		cur = con.cursor()
		cur.execute("SELECT * FROM connections")
		connections = cur.fetchall()
		cur.execute("SELECT * FROM flows")
		flows = cur.fetchall()
	
		print "ID"+"\tDir"+"\tSvrIP"+"\t\tClntIP"+"\t\tSvrPrt"+"\tClntPrt"+"\tTime"+"\t\tPayload Size"
		
		for flow in flows:
			
			connection=flow[0]
			
			direction=flow[1]
			serverip=connections[connection][1]
			clientip=connections[connection][3]
			serverport=connections[connection][2]
			clientport=connections[connection][4]
			timestamp=flow[3]
			message=flow[4][1:][:-1]
			decode_hex = codecs.getdecoder("hex_codec")
			message=message.replace('\\x','DELI\\x')
			parts = message.split('DELI')
			
			message=''
			for p in parts:
				if '\\x' in p:
					if len(p) == 4:
						message=message+p.replace('\\x','')
					else:
						message=message+p.replace('\\x','')[:2]
						message=message+p.replace('\\x','')[2:].encode("hex")
				else:
					message=message+p.encode("hex")


			print "{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}".format(connection,direction,serverip,clientip,serverport,clientport,timestamp,len(message))

			if direction =="c2s":
				dstaddr=socket.inet_aton(serverip)
				dstaddr=''.join( [ "%02X " % ord( x ) for x in dstaddr ] ).strip()
				srcaddr=socket.inet_aton(clientip)
				srcaddr=''.join( [ "%02X " % ord( x ) for x in srcaddr ] ).strip()
			else:
				dstaddr=socket.inet_aton(clientip)
				dstaddr=''.join( [ "%02X " % ord( x ) for x in dstaddr ] ).strip()
				srcaddr=socket.inet_aton(serverip)
				srcaddr=''.join( [ "%02X " % ord( x ) for x in srcaddr ] ).strip()

			srcprt = '%04X' % (clientport)
			srcprt = ' '.join(srcprt[i:i+2] for i in range(0, len(srcprt), 2))
			
			dstprt = '%04X' % (serverport)
			dstprt = ' '.join(dstprt[i:i+2] for i in range(0, len(dstprt), 2))
			
			generatePCAP(srcaddr, dstaddr,srcprt,dstprt,message)

def splitkeepsep(s, sep):
    return reduce(lambda acc, elem: acc[:-1] + [acc[-1] + elem] if elem == sep else acc + [elem], re.split("(%s)" % re.escape(sep), s), [])
			
def asciirepl(match):
  s = match.group()  
  return binascii.unhexlify(s)  

def reformat_content(data):
  p = re.compile(r'\\x(\w{2})')
  return p.sub(asciirepl, data)
  
def getByteLength(str1):
	return len(''.join(str1.split())) / 2

def writeByteStringToFile(bytestring, filename):
	bytelist = bytestring.split() 
	bytes = binascii.a2b_hex(''.join(bytelist))
	bitout = open(filename, 'ab')
	bitout.write(bytes)

def writeheader():
	pcap_global_header =   ('D4 C3 B2 A1' 
							'02 00'		 #File format major revision (i.e. pcap <2>.4)
							'04 00'		 #File format minor revision (i.e. pcap 2.<4>)
							'00 00 00 00'
							'00 00 00 00'
							'FF FF 00 00'
							'01 00 00 00')
	writeByteStringToFile(pcap_global_header, sys.argv[2])

def generatePCAP(srcaddr, dstaddr,srcprt,dstprt,message): 

	port =123
	#pcap packet header that must preface every packet
	pcap_packet_header =   ('AA 77 9F 47'
							'90 A2 04 00'
							'XX XX XX XX'   #Frame Size (little endian)
							'YY YY YY YY') #Frame Size (little endian)

	eth_header =   ('00 0C 29 65 25 A8'	 #Source Mac
					'8C 89 A5 0E 33 FE'	 #Dest Mac
					'08 00').replace(' ','')				#Protocol (0x0800 = IP)

	ip_header =	('45'					#IP version and header length (multiples of 4 bytes)
					'00'
					'XX XX'				 #Length - will be calculated and replaced later
					'00 DA'
					'40 00 80'
					'06'					#Protocol (0x11 = UDP)
					'YY YY'				 #Checksum - will be calculated and replaced later
					+ srcaddr +		  #Dest IP (Default: 127.0.0.1)
					dstaddr)		  #Dest IP (Default: 127.0.0.1)
	

	udp_header =   (srcprt +
					dstprt +				#Port - will be replaced later
					'A4 7C A0 9B'		   #sequence number
					'B7 2E FD 69'					   #ackwnledgement number
					'50 18'				 #Length - will be calculated and replaced later
					'D0 00'				 #window size value
					'FA C5'			 #checksum
					'00 00'	 )		   #urgent pointer

	udp = udp_header
	ip = ip_header

	udp = udp_header.replace('XX XX',"%04x"%port)
	udp_len = getByteLength(message) + getByteLength(udp_header)
	udp = udp.replace('YY YY',"%04x"%udp_len)
	

	ip_len = udp_len + getByteLength(ip_header)
	ip = ip.replace('XX XX',"%04x"%ip_len)
	checksum = ip_checksum(ip.replace('YY YY','00 00'))
	ip = ip.replace('YY YY',"%04x"%checksum)
	
	
	pcap_len = ip_len + getByteLength(eth_header)
	hex_str = "%08x"%pcap_len
	reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
	pcaph = pcap_packet_header.replace('XX XX XX XX',reverse_hex_str)
	pcaph = pcaph.replace('YY YY YY YY',reverse_hex_str)
	
	bytestring = pcaph + eth_header + ip + udp + message
	writeByteStringToFile(bytestring.replace(' ','') , sys.argv[2])

def splitN(str1,n):
	return [str1[start:start+n] for start in range(0, len(str1), n)]


def chunkstring(string, length):
	return (string[0+i:length+i] for i in range(0, len(string), length))

#Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):

	#split into bytes	
	words = splitN(''.join(iph.split()),4)

	csum = 0;
	for word in words:
		csum += int(word, base=16)

	csum += (csum >> 16)
	csum = csum & 0xFFFF ^ 0xFFFF

	return csum


main()

