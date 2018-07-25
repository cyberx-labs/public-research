#!/usr/bin/env python
#     
# vpnfilter_backdoor_check.py - Identify presence of VPNFilter backdoor
# Copyright (C) 2018 CyberX
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from scapy.all import *
import socket
import sys

def listen_to_443():
    serversock = socket.socket() 
    serversock.bind(('0.0.0.0', 443))
    serversock.listen(1)
    serversock.settimeout(5)

    try:
        clientsock, addr = serversock.accept()
        print ("VPNFilter backdoor found")
    except:
        print ("VPNFilter backdoor not found")

def scan_ip(dst):
    sport = 3333
    dport = 80
    src = socket.gethostbyname(socket.gethostname())
    ip = IP(src=src, dst=dst)
    SYN = TCP(sport=sport, dport=dport, flags='S', seq=1000)
    xsyn = ip / SYN / ('\x0c\x15\x22\x2b' + ''.join(map(lambda x: chr(int(x)), src.split('.'))))

    send(xsyn, verbose=False)

if len(sys.argv) < 2:
    print ('%s <ip>' % sys.argv[0])
else:
    Thread(target=listen_to_443).start()
    scan_ip(sys.argv[1])
