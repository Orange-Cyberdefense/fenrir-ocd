# coding=utf-8

from scapy.all import *
from FenrirTail import FenrirTail

class FenrirFangs:

	def __init__(self, debugLevel=1):
		self.debugLevel = debugLevel
		self.FenrirTail = FenrirTail(debugLevel)
		self.userRules = []
		self.ruleCount = 0
		#self.addRule(137, 'IP', 'multi')
		#self.addRule(5355, 'IP', 'multi')
		#self.addRule(80,'IP', 'multi')
		#self.addRule(445,'IP','unique')

	def addRule(self, pdst, proto='IP', ruleType='unique'):
		userRule = FenrirRule(pdst, proto, ruleType)
		self.userRules.append(userRule)
		self.ruleCount = self.ruleCount + 1

	def checkRules(self, pkt):
		for rule in self.userRules:
			if rule.pktMatch(pkt) == True:
				if rule.type == 'unique':
					self.userRules.remove(rule)
					self.ruleCount = self.ruleCount - 1
				return True
		#if 'IP' in pkt and pkt[IP].src == '10.0.0.69':
		#	print('DEDANS')
		#	return True
		return False

	def changeVerbosity(self, debugLevel):
		self.debugLevel = debugLevel





class FenrirRule:

	def __init__(self, pdst, proto='IP', ruleType='unique'):
		self.dst_port = pdst
		self.proto = proto
		self.type = ruleType

	def pktMatch(self, pkt):
		epkt = pkt
		try:
			if self.proto in epkt:
				if 'IP' in epkt and epkt['IP'].dport == self.dst_port:
					return True
				else:
					if epkt[self.proto].dport == self.dst_port:
						return True
					else:
						return False
			else:
				return False
		except:
			return False
