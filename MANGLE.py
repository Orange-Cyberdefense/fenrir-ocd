# coding=utf-8
####################################################################
##|# ----------- This is MANGLE, aka FENRIR's core ----------- #|###
##|# - It is responsible for handling the NAT Logic and the  - #|###
##|# - Mangling of packets as they go through the interface  - #|###
##|# --------------------------------------------------------- #|###
##|# -   New modules for Layer 3 protocols can be added by   - #|###
##|# - importing them and modifying the FAT (Fenrir_Address_ - #|###
##|# -          Translation) function ("else" part)          - #|###
####################################################################

from scapy.all import *
from modARP import modARP
from modICMP import modICMP
from FenrirTail import FenrirTail


##########################################################
### --- Main component implementing the NAT LOGIC --- ####
##########################################################
class MANGLE:
	def __init__(self, ip_host, ip_rogue, mac_host, mac_rogue, debugLevel=1):
		self.banner()
		print('\n')
		print '\033[1m\033[32m[*] FENRIR is waking up...\033[0m'
		self.FenrirTail = FenrirTail(debugLevel)
		self.FenrirTail.notify('Loading FenrirTail...', 1)
		self.debugLevel = debugLevel
		self.host = ip_host
		self.rogue = ip_rogue
		self.mrogue = mac_rogue
		self.mhost = mac_host
		self.PKTthreads = []
		self.pktNumber = 0
		self.threshold = self.FenrirTail.threshold
		self.PKTthread_number = 0
		self.PKTthread_index = 0
		self.FILTER = Fenrir_Internal_Light_Trafic_Efficient_Ruling(debugLevel)
		self.modARP = modARP(ip_host, ip_rogue, mac_host, mac_rogue, debugLevel)
		self.modICMP = modICMP(ip_host, ip_rogue, mac_host, mac_rogue, debugLevel)
		self.FenrirTail.notifyGood('FENRIR init complete ! Ready to process trafic...\n', 1, 1)

	## NAT LOGIC ##
	def Fenrir_Address_Translation(self, pkt):
		self.FenrirTail.notify('\033[7m--- ProcessPKT ---\033[27m', 3)
		self.pktNumber += 1
		if 'TCP' in pkt or 'UDP' in pkt:
			self.FenrirTail.notify('IP packet received. Entering IP processing routines...', 3)
			if self.FILTER.FILTER_routine(pkt):  # Fenrir's Internal Light-Traffic Efficient Ruling
				current_PKTthread = self.PKTthread_exist(pkt)
				#current_PKTthread.gatherSeqNum(pkt)
				IPpkt = self.Fenrir_Mangling(pkt, current_PKTthread)
				self.FenrirTail.notify('IP packet sent', 3)
				self.closeConn_sniff(pkt, current_PKTthread)
				return IPpkt
			else:
				self.FenrirTail.notify('Packet got dropped by FILTER', 2)
				self.FenrirTail.notify(str(ls(pkt)), 3)
				return False
		# Else, we may need some exceptional processing (ARP stuff, etc...)
		else:
			self.FenrirTail.notify('Non-TCP/UDP packet received. Entering special processing routines...', 3)
			if 'ARP' in pkt:
				ARPpkt = self.modARP.Fenrir_Address_Resolution_Protocol(pkt)
				self.FenrirTail.notify('ARP packet sent', 3)
				return ARPpkt
			elif 'ICMP' in pkt:
				ICMPpkt = self.modICMP.Fenrir_Control_Message_Protocol(pkt)
				self.FenrirTail.notify('ICMP packet sent', 3)
				return ICMPpkt
			elif 'EAPOL' in pkt:
				self.FenrirTail.notify('EAPOL packet sent', 3)
				return pkt.__class__(str(pkt))
			self.FenrirTail.notify('No special packet handlers found... Forwarding packets', 3)
			return pkt
			#### INSERT HERE LAYER 3 IMPLEMENTATION MODULES CALLS

	## Find PKTthread associated with a packet ##
	def PKTthread_exist(self, pkt):
		for PKTthread in self.PKTthreads:
			if PKTthread.thisIsMyPKT(pkt) == True:
				self.FenrirTail.notify('PKTthread exists...', 2)
				return PKTthread
		self.FenrirTail.notify('New PKTthread detected. Creation...', 2)
		return self.create_PKTthread(pkt)

	## Create a new PKTthread upon receiving new packet ##
	def create_PKTthread(self, pkt):
		if pkt[IP].dst == self.host or pkt[IP].dst == self.rogue:
			return self.create_PKTthread_from_reverseCon(pkt)
		else:
			return self.create_PKTthread_from_bindCon(pkt)

	def create_PKTthread_from_reverseCon(self, pkt):
		PKTthreadInstance = PKTthread(pkt.dport, pkt.sport, pkt[IP].dst, pkt[IP].src, [-1,-1], 'active')
		self.PKTthreads.append(PKTthreadInstance)
		self.PKTthread_number += 1
		self.FenrirTail.notify('PKTthread created from reverse connection', 3)
		return PKTthreadInstance

	def create_PKTthread_from_bindCon(self, pkt):
		PKTthreadInstance = PKTthread(pkt.sport, pkt.dport, pkt[IP].src, pkt[IP].dst, [-1,-1], 'active')
		self.PKTthreads.append(PKTthreadInstance)
		self.PKTthread_number += 1
		self.FenrirTail.notify('PKTthread created from bind connection', 3)
		return PKTthreadInstance

	## Deletion of complete PKTthread ##
	def deletePKTthread(self, PKTthread):
		try:
			self.PKTthreads.remove(PKTthread)
			self.PKTthread_number -= 1
			self.FenrirTail.notify('PKTthread deleted', 3)
			return True
		except:
			self.FenrirTail.fenrirPanic('Unexpected exception was raised during deletion of PKTthread : PKTthread does not exist (this can happen...)', 0, 0)
			return True

	## Mangling manager ##
	def Fenrir_Mangling(self, pkt, PKTthread):
		if pkt[IP].src == self.host:  # Packet for network on a host-network Pthread, no need for mangling
			self.FenrirTail.notify('Packet from host to network - FORWARD', 2)
			return pkt
		elif pkt[IP].dst == self.host and PKTthread.src_ip == pkt[IP].dst: # Packet for host on a host-network Pthread, no need for mangling
			self.FenrirTail.notify('Packet from network to host - FORWARD', 2)
			return pkt
		elif pkt[IP].dst == self.host and PKTthread.src_ip == self.rogue:  # Packet for host on a rogue-network Pthread, mangling needed
			newPKT = self.pktRewriter(pkt, pkt[IP].src, self.rogue, pkt[Ether].src, self.mrogue)
			return newPKT
		elif pkt[IP].src == self.rogue:  # Packet for network on a rogue-network Pthread, mangling needed
			newPKT = self.pktRewriter(pkt, self.host, pkt[IP].dst, self.mhost, pkt[Ether].dst)
			newPKT = PKTthread.mangleSeqNum1(newPKT)
			return newPKT
		else:
			#self.FenrirTail.fenrirPanic('Unknown situation while matching PKTthread',0,0)
			return pkt

	## Rewrite packet IPs and MACs ##
	def pktRewriter(self, pkt, src, dst, msrc, mdst):
		self.FenrirTail.notify('IP packet is being rewritten :', 3)
		if pkt[IP].src != src:
			self.FenrirTail.notify('\t' + pkt[IP].src + ' --> ' + src, 3)
			pkt[IP].src = src
		if pkt[IP].dst != dst:
			self.FenrirTail.notify('\t' + pkt[IP].dst + ' --> ' + dst, 3)
			pkt[IP].dst = dst
		if pkt[Ether].src != msrc:
			self.FenrirTail.notify('\t' + pkt[Ether].src + ' --> ' + msrc, 3)
			pkt[Ether].src = msrc
		if pkt[Ether].dst != mdst:
			self.FenrirTail.notify('\t' + pkt[Ether].dst + ' --> ' + mdst, 3)
			pkt[Ether].dst = mdst
		del pkt[IP].chksum  # 2 lines for recalculation of checksum
		if 'TCP' in pkt:
			del pkt[TCP].chksum
		if 'IP' in pkt:
			del pkt[IP].len
		pkt = pkt.__class__(str(pkt))
		self.FenrirTail.notify('IP packet mangled and rewritten successfully', 3)
		return pkt

	## Checks for connection termination from host/rogue/remote which implies PKTthread deletion ##
	def closeConn_sniff(self, pkt, PKTthread):
		# definitions for binary AND
		FIN = 0x01
		SYN = 0x02
		RST = 0x04
		PSH = 0x08
		ACK = 0x10
		URG = 0x20
		ECE = 0x40
		CWR = 0x80
		if 'TCP' in pkt:
			if pkt[TCP].flags & RST:
				self.FenrirTail.notifyWarn('RST packet went through. Deleting associated PKTthread...', 3)
				self.deletePKTthread(PKTthread)
				return True
			elif pkt[TCP].flags & FIN:
				self.FenrirTail.notify('FIN packet went through. Checking PKTthread state...', 3)
				if PKTthread.state == 'active':
					PKTthread.changeState('FIN_sent')
					self.FenrirTail.notify('\tPKTthread state changed to  "FIN_sent"', 3)
					return False
				elif PKTthread.state == 'FIN_sent':
					PKTthread.changeState('FIN_acknowledged')
					self.FenrirTail.notify('\tPKTthread state changed to "FIN_acknowledged"', 3)
					return False
				elif PKTthread.state == 'FIN_acknowledged':
					self.FenrirTail.fenrirPanic(
						'Unexpected exception was raised during deletion of PKTthread (this can happen)', 0, 0)  # if we receive a FIN packet when a first FIN was acknowledged, something's fucky ! (packet got dropped ?)
				else:
					self.FenrirTail.fenrirPanic('PKTthread is in unknown state : ' + pkt)
					exit()
			elif (pkt[TCP].flags & ACK) and PKTthread.state == 'FIN_acknowledged':
				self.FenrirTail.notify('ACK packet went through for a terminating PKTthread. Checking PKTthread state...', 3)
				PKTthread.changeState('zombie')
				self.FenrirTail.notifyWarn('\tPKTthread state changed to "zombie"', 3)
				self.deletePKTthread(PKTthread)

	## Iterator Methods ##
	def __iter__(self):
		return self

	def next(self):
		if PKTthread_number > 0 and PKTthread_index != PKTthread_number:
			self.PKTthread_index += 1
			return self.PKTthreads[self.PKTthread_index]
		else:
			raise StopIteration

	
	## TCP Sequence number modification ##
	def changeSessID(self, pkt):
		currentPKTthread = self.PKTthread_exist(pkt)
		PUSH = 0x08
		#currentPKTthread.len1 = pkt[IP].len
		if pkt[TCP].flags & PUSH:
			print("dedans")
			pkt[TCP].seq = currentPKTthread.oldseq1 + currentPKTthread.oldlen1 + 1
			print("PKT TCP SEQ = " + str(currentPKTthread.oldseq1) + " + " + str(currentPKTthread.oldlen1) + " + 1 = " + str(pkt[TCP].seq))
		return pkt


	def banner(self) :
		print("\n\033[1m")
		print("                                                      ,a8b")
		print("                                                  ,,od8  8")
		print("                                                 d8'     8b")
		print("                                              d8'ba     aP'")
		print("                                           o8'         aP'")
		print("                                            YaaaP'    ba")
		print("                           \033[31mFENRIR\033[0m\033[1m         Y8'         88")
		print("                                       ,8\"           `P")
		print("                                  ,d8P'              ba")
		print("                  ooood8888888P\"\"\"'                  P'")
		print("               ,od                                  8")
		print("            ,dP     o88o                           o'")
		print("           ,dP          8                          8")
		print("          ,d'   oo       8                       ,8")
		print("          $    d$\"8      8           Y    Y  o   8")
		print("         d    d  d8    od  \"\"boooaaaaoob   d\"\"8  8")
		print("         $    8  d  ood'-I   8         b  8   '8  b")
		print("         $   $  8  8     d  d8        `b  d    '8  b")
		print("          $  $ 8   b    Y  d8          8 ,P     '8  b")
		print("          `$$  Yb  b     8b 8b         8 8,      '8  o,")
		print("               `Y  b      8o  $$       d  b        b   $o")
		print("                8   '$     8$,,$\"      $   $o      '$o$$")
		print("                $o$$P\"                 $$o$")
		print("\033[0m")


####################################################################
### --- Class representing an IP connection between 2 hosts --- ####
####################################################################
class PKTthread:
	states = ['active', 'reset', 'FIN_sent', 'FIN_acknowledged', 'zombie', 'collided']

	# SOURCE is always from the host point of view (spoofed/rogue host)
	def __init__(self, psrc, pdst, asrc, adst, seqList, activity="active"):
		self.src_port = psrc
		self.src_ip = asrc
		self.dst_port = pdst
		self.dst_ip = adst
		self.state = activity
		self.sequence = seqList # sequence numbers storage
		self.oldseq1 = 0
		self.seq1 = 0
		self.oldlen1 = 0
		self.len1 = 0
		self.oldseq2 = 0
		self.seq2 = 0
		self.oldlen2 = 0
		self.len2 = 0

	## Returns True if a packet is part of the PKT ##
	def thisIsMyPKT(self, pkt):
		# host->server check first
		if pkt[IP].dst == self.dst_ip and pkt.sport == self.src_port and pkt.dport == self.dst_port:
			#self.sequence[0] = pkt[IP].seq
#			if 'TCP' in pkt:
#				self.gatherTCPSessID1(pkt)
			return True
		# server->host check
		elif pkt[IP].src == self.dst_ip and pkt.dport == self.src_port and pkt.sport == self.dst_port:
			#self.sequence[1] = pkt[IP].seq
#			if 'TCP' in pkt:
#				self.gatherTCPSessID2(pkt)
			return True
		else:
			return False

	## Gathering of Seq numbers ##
	def gatherSeqNum(self, pkt):
		if pkt[IP].dst == self.dst_ip and pkt.sport == self.src_port and pkt.dport == self.dst_port:
			if 'TCP' in pkt:
				self.gatherTCPSessID1(pkt)
		elif pkt[IP].src == self.dst_ip and pkt.dport == self.src_port and pkt.sport == self.dst_port:
			if 'TCP' in pkt:
				self.gatherTCPSessID2(pkt)


	## Wrapper around the state change ##
	def changeState(self, newState):
		if self.state != 'zombie':
			self.state = newState
		else:
			exit(
				"PKTThread in unstable state : '" + self.state + "' - Look for the 'changeState' function in MANGLE.py")

	## Dump function used in logging ##
	def threadDump(self):
		dump = self.src_ip + " ---> " + self.dst_ip + "\n"
		dump = dump + "port " + self.src_port + " to " + self.dst_port
		return dump
	
	## Gathering of TCP session for PKTthread updating ##
	def gatherTCPSessID1(self, pkt) :
		if 'TCP' in pkt:
			self.oldseq1 = self.seq1
			self.seq1 = pkt[TCP].seq
			self.oldlen1 = self.len1
			self.len1 = pkt[IP].len - 52
			print("self.len1 = " + str(pkt[IP].len) + " - 52 = " + str(self.len1))
		else:
			exit("FENRIR PANIC : non TCP packet was sent to gatherTCPSessID. This should not happen") 

	def gatherTCPSessID2(self, pkt) :
		self.oldseq2 = self.seq2
		self.seq2 = pkt[TCP].seq
		self.oldlen2 = self.len2
		self.len2 = pkt[IP].len - 52
		#print("IN 2")

	def mangleSeqNum1(self, pkt):
		if 'TCP' in pkt :
			self.oldseq1 = self.seq1
			self.oldlen1 = self.len1
			#if pkt[TCP].flags & 0x08:
			if not self.oldseq1 == 0:
				pkt[TCP].seq = self.oldseq1 + self.oldlen1
				if pkt[TCP].flags & 0x10 and not pkt[TCP].flags & 0x08:
					pkt[TCP].seq = pkt[TCP].seq + 1
				del pkt[TCP].chksum
				pkt = pkt.__class__(str(pkt))
			self.seq1 = pkt[TCP].seq
			self.len1 = len(pkt[TCP].payload)
		return pkt


########################################################################
### --- FILTER : Fenrir's Internal Light-Trafic Efficient Ruling --- ###
######## --- Class implementing some Fenrir-level filtering --- ########
########################################################################

### THIS CLASS IS DECOMMISSIONNED !!! ###
class Fenrir_Internal_Light_Trafic_Efficient_Ruling():
	actions = ['drop', 'log']

	def __init__(self, debugHerited, rulesToLoad=[], specialRulesToLoad=[], filename='FENRIR.log'):
		self.FenrirTail = FenrirTail(debugHerited)
		self.enabled = False
		self.FenrirTail.notify('Loading FILTER module...', 1)
		self.logfile = filename
		self.rules = rulesToLoad
		self.specialRules = []
		if len(rulesToLoad) > 0 or len(specialRulesToLoad) > 0:
			self.FenrirTail.notify('\tRule(s) loaded successfully (' + (len(rulesToLoad) + len(specialRulesToLoad)) + ' rule(s))',
			            2)
		else:
			self.FenrirTail.notify('\tNo rule to load', 2)
			self.enabled = False

	## Main FILTER's routine : returns False if packet is dropped (The method also takes other ations in charge e.g. logging) ##
	def FILTER_routine(self, pkt):
		if self.enabled == False:
			return True
		else:
			for rule in self.specialRules:
				if rule[0] == pkt.sport or rule[0] == pkt.dport:
					self.FenrirTail.notify('Special rule applied (port : ' + rule[2] + ') [Packet DROPPED]', 3)
					return False
			for rule in self.rules:
				if applyRule(rule, pkt) == True:
					return False
			return True

	## Apply rule to packet and execute function associated to action; returns True if action is drop ##
	def applyRule(self, rule, pkt):
		if pkt[IP].src == rule[0] or pkt[IP].dst == rule[0]:
			if pkt.sport == rule[1] or pkt.dport == rule[1]:
				action = rule[3]
				self.FenrirTail.notify('Rule applied (port : ' + rule[1] + ', action : ' + rule[2] + ')', 3)
				return action()

	## Add rule for host(s) ##
	def ruleAdd(self, host, port, action='drop'):
		if host == '*':
			newRule = [port, action]
			self.specialRules.append(newRule)
		else:
			newRule = [host, port, action]
			self.rules.append(newRule)
		self.FenrirTail.notify('Rule added', 3)

	#### ACTION SET ####
	def drop(self, pkt):
		return True

	def log(self, pkt):
		logfd = open(self.logfile, 'a')
		logfd.write(
			'[*] Packet received FROM ' + pkt[IP].src + ' (' + pkt[Ether].src + ') GOING TO ' + pkt[IP].dst + ' (' +
			pkt[Ether].dst + ')\n')
		logfd.close()
		self.notify('Log written to logfile : ' + self.logfile, 3)
		return False

	## Notifier ##
	# def notify(self, errMsg, verbosityLevel):
	# 	if self.debug >= verbosityLevel:
	# 		print '[-- ' + errMsg
