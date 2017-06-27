# coding=utf-8
######################################################################
##|# ------ FenrirTail : Fenrir logging and output class ----- #|###
##|# -    It is responsible for printing error/debug/info    - #|###
##|# -                 messages to the user                  - #|###
######################################################################

from scapy.all import *
from sys import stdout


###########################################################################
### ---------------- Main component of FenrirTail ---------------- ####
###########################################################################
class FenrirTail :

	def __init__(self, debugLevel=1) :
		self.debug = debugLevel
		self.threshold = 100


	def packetCounter(self, pkt, pktNumber, PKTthread_number):
		stdout.write("\r\033[1m\033[32m[RAWR]\033[0m Processing packet number\033[1m \033[31m" + str(
			pktNumber))
		stdout.flush()


	# Verbosity : 0 = no msg, 1 = normal, 2 = information (light), 3 = this damn tool won't stop printing stuff
	## Notify : main function for standard output ##
	def notify(self, msg, verbosityLevel, bold=0) :
		if self.debug >= verbosityLevel :
			if bold == 1:
				msg = '\033[1m' + msg + '\033[0m'
			else:
				msg = '[-- ' + msg
			print msg


	## notifyGood : green color ##
	def notifyGood(self, msg, verbosityLevel, bold=0) :
		if self.debug >= verbosityLevel :
			msg = '\033[32m[*] ' + msg + '\033[0m'
			self.notify(msg, verbosityLevel, bold)


	## notifyWarn : yellow color ##
	def notifyWarn(self, msg, verbosityLevel, bold=0) :
		if self.debug >= verbosityLevel :
			msg = '\033[33m[*] ' + msg + '\033[0m'
			self.notify(msg, verbosityLevel, bold)


	## notifyBad : red color ##
	def notifyBad(self, msg, verbosityLevel, bold=0) :
		if self.debug >= verbosityLevel :
			msg = '\033[31m[*] ' + msg + '\033[0m'
			self.notify(msg, verbosityLevel, bold)


	## mangleException : responsible for writing mangle exceptions logs to file ## 
	def mangleException(self, pkt, reason=''):
		self.notifyBad('\nFENRIR PANIC : Process failed during MANGLING', 1, 1)
		if reason != '':
			self.notifyBad('Reason : ' + reason, 1)
		self.notify('Packet was logged to errorLogFile : FENRIR.err', 1)
		logfd = open('FENRIR.err', 'a')
		logfd.write(
			'---DUMP BEGINS--------------------------------------------------------------------------------------\n')
		logfd.write(
			'[*] Packet header SRC : ' + pkt[IP].src + ' (' + pkt[Ether].src + ') DST : ' + pkt[IP].dst + ' (' + pkt[
				Ether].dst + ')\n')
		logfd.write('Packet dump :\n')
		logfd.write(str(ls(pkt)) + '\n')
		logfd.write(
			'---DUMP ENDS----------------------------------------------------------------------------------------\n')
		logfd.close()


	## fenrirPanic : unrecoverable exception handling ##
	def fenrirPanic(self, msg, bold=1, exitOnFailure=1) :
		if bold == 1 :
			msg = '\033[1m' + 'FENRIR PANIC : ' + msg + '\033[0m'
		else :
			msg = 'FENRIR PANIC : ' + msg
		if exitOnFailure == 1 :
			exit(msg)
		else :
			print msg
