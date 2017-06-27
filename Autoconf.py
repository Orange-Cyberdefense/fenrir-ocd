# coding=utf-8

import socket
from scapy.all import *


class Autoconf :

	def __init__(self):
		self.hostmac = ""
		self.hostip = ""
		self.conf = True
		self.ifaceHost = "em1"
		self.ifaceNetwork = "eth0"
		self.sockHost = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
		self.sockNetwork = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
		try:
			self.sockHost.bind((self.ifaceHost, 0))
			self.sockNetwork.bind((self.ifaceNetwork, 0))
		except:
			#exit("You need 2 physical network interfaces to use FENRIR !")
			print("You need 2 physical network interfaces to use FENRIR !")
		self.inputs = [self.sockHost, self.sockNetwork]

	def startAutoconf(self):
		print "Trying to detect @mac and @ip of spoofed host..."
		while self.conf == True :
			try:
				inputready,outputready,exceptready = select.select(self.inputs, [], [])
			except select.error, e:
				break
			except socket.error, e:
				break
			for socketReady in inputready :
					#We check packets from iface1 and fwd them to iface2
					if socketReady == self.sockHost :
						packet = self.sockHost.recvfrom(1500)
						pkt = packet[0]
						dpkt = Ether(packet[0])
						if 'ARP' in dpkt :
							self.hostmac = dpkt[Ether].src
						elif 'IP' in dpkt :
							self.hostip = dpkt[IP].src
							self.hostmac = dpkt[Ether].src							
						#We send the packet to the other interface
						self.sockNetwork.send(pkt)
					#We forward packet from iface2 to iface1		
					if socketReady == self.sockNetwork :
						packet = self.sockNetwork.recvfrom(1500)
						pkt = packet[0]
						self.sockHost.send(pkt)
			if self.hostip != "" and self.hostmac !=  "" :
				#self.conf = False
				return self.hostip, self.hostmac