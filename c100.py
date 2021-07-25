import socket
import os
import sys
import subprocess
import re

from pythonping import ping

email_reg = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

# c100 is a hit at c99 and their api that you HAVE to pay for, imagine having money?
# This api is open source, free, and I like feedback so send me shit you would want to see in here.
# I will also be writing a api tool for C! it will allow you to interface with the c100 api(which is python if you didn't have a brain)
# inside of your C programs!

# The port checker, kinda rocky, but it works
def checkPort(addr, prt):
    tmpSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmpSock.settimeout(0.2)
    loc = (addr, prt)
    result = tmpSock.connect_ex(loc)
    tmpSock.close()

    if result == 0:
        return True
    else:
        return False

# The DNS resolver
def getIpFromHost(host):
    res = socket.gethostbyname(host)
    return res

# The ping tool
def pingHost(host):
    r = 0

    try:
        ping(host)
        r = 1
    except Exception:
        r = 0


    if r == 0:
        return False
    else:
        return True

# Port Scanner
# Error List
# 0 = hostname invalid
# 1 = connection error
# 2 = Cancelled
# Else return type will be an array
def portScan(host):
    try:
        openprts = []
        for port in range(1, 1025):
            tmpSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tmpSock.settimeout(0.1)
            result = tmpSock.connect_ex((host, port))
            if result == 0:
                openprts.append(port)
            tmpSock.close()
        
        return openprts
    except KeyboardInterrupt:
        if openprts != []:
            return openprts
        else:
            return 2
    except socket.gaierror:
        return 0
    except socket.error:
        return 1

# Validate Email
def checkEmail(email):
    if(re.match(email_reg, email)):
        return 1
    else:
        return 0

# Whois ---
def perform_whois(server , query) :
	#socket connection
	s = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
	s.connect((server , 43))
	
	#send data
	s.send(str(query + '\r\n').encode())
	
	#receive reply
	msg = ''
	while len(msg) < 10000:
		chunk = s.recv(100).decode()
		if(chunk == ''):
			break
		msg = msg + chunk
	
	return msg

def getWhoIs(domain):
	#remove http and www
    domain = domain.replace('http://','')
    domain = domain.replace('www.','')
	
	#get the extension , .com , .org , .edu
    ext = domain[-3:]
	
	#If top level domain .com .org .net
    if(ext == 'com' or ext == 'org' or ext == 'net'):
        whois = 'whois.internic.net'
        msg = perform_whois(whois , domain)
		
		#Now scan the reply for the whois server
        lines = msg.splitlines()
        for line in lines:
            if ':' in line:
                words = line.split(':')
                if  'Whois' in words[0] and 'whois.' in words[1]:
                    whois = words[1].strip()
                    break
	
	#Or Country level - contact whois.iana.org to find the whois server of a particular TLD
    else:
		#Break again like , co.uk to uk
        ext = domain.split('.')[-1]
		
		#This will tell the whois server for the particular country
        whois = 'whois.iana.org'
        msg = perform_whois(whois , ext)
		
		#Now search the reply for a whois server
        lines = msg.splitlines()
        for line in lines:
            if ':' in line:
                words = line.split(':')
                if 'whois.' in words[1] and 'Whois Server (port 43)' in words[0]:
                    whois = words[1].strip()
                break
	
	#Now contact the final whois server
    msg = perform_whois(whois , domain).split(">>>")[0]

	
	#Return the reply
    return msg

# Whois ---


