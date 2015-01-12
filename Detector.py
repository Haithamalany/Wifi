#!\usr\bin\env python

#To monitor Deauth/Diass Attacks on Wireless Access Points

import sys
import os
from scapy.all import *

#Enabling Monitor Mode

os.system("airmon-ng start wlan0")  

interface = 'mon0'

try:

	print "\nThis tool monitors the air to detect any Deauth/Diass attack\n"

	print "Coded by @haithamalany\nMonitoring on progress..." 

	#Start Sniffing 

	def sniffReq(p):

	#In case there was Deauth Attack 

     		if p.haslayer(Dot11Deauth):


       			  print p.sprintf("Deauthentication Attack Found from AP [%Dot11.addr2%]  	Client [%Dot11.addr1%], Reason [%Dot11Deauth.reason%]")

    
	#In case there was Diass Attack 

     		elif p.haslayer(Dot11Disas):

		                   print p.sprintf("Diassociation Attack Found from AP [%Dot11.addr2%]  	Client [%Dot11.addr1%], Reason [%Dot11Deauth.reason%]")

except:
	
  	print "Could not find your wifi adapter"

sniff(iface=interface,prn=sniffReq)
