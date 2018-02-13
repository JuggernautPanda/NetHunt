#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  NetHunt_Analysis_Tool.py
#  PwC:(NetHunt™)
#  Copyright 2018 raja <raja@raja-Inspiron-N5110>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  Example analyzing script for saved exports (as JSON).
#  http://pythonhosted.org/python-geoip/

from geoip import geolite2
from datetime import datetime
import ipaddress
import json
import os.path
import sys
import socket
from collections import namedtuple

Pair = namedtuple('Pair', 'src dest')

def FetchIPs(flow):
    if flow['IP_PROTOCOL_VERSION'] == 4:
        return Pair(
            ipaddress.ip_address(flow['IPV4_SRC_ADDR']),
            ipaddress.ip_address(flow['IPV4_DST_ADDR']))

    elif flow['IP_PROTOCOL_VERSION'] == 6:
        return Pair(
            ipaddress.ip_address(flow['IPV6_SRC_ADDR']),
            ipaddress.ip_address(flow['IPV6_DST_ADDR']))


class Connection:
    """Connection model for two flows.
    The direction of the data flow can be seen by looking at the size.

    'src' describes the peer which sends more data towards the other. This
    does NOT have to mean, that 'src' was the initiator of the connection.
    """
    def __init__(self, flowA, flowB):
        if flowA['IN_BYTES'] >= flowB['IN_BYTES']:
            src = flowA
            dest = flowB
        else:
            src = flowB
            dest = flowA

        ips = FetchIPs(src)
        self.src = ips.src
        self.dest = ips.dest
        self.src_port = src['L4_SRC_PORT']
        self.dest_port = src['L4_DST_PORT']
        self.size = src['IN_BYTES']

        # Duration is given in milliseconds
        self.duration = src['LAST_SWITCHED'] - src['FIRST_SWITCHED']
        if self.duration < 0:
            # 32 bit int has its limits. Handling overflow here
            self.duration = (2**32 - src['FIRST_SWITCHED']) + src['LAST_SWITCHED']

    def __repr__(self):
        return "<Connection from {} to {}, size {}>".format(
            self.src, self.dest, self.human_size)

    @property
    def human_size(self):
        # Calculate a human readable size of the traffic
        if self.size < 1024:
            return "%dB" % self.size
        elif self.size / 1024. < 1024:
            return "%.2fK" % (self.size / 1024.)
        elif self.size / 1024.**2 < 1024:
            return "%.2fM" % (self.size / 1024.**2)
        else:
            return "%.2fG" % (self.size / 1024.**3)

    @property
    def human_duration(self):
        duration = self.duration // 1000  # uptime in milliseconds, floor it
        if duration < 60:
            # seconds
            return "%d sec" % duration
        if duration / 60 > 60:
            # hours
            return "%d:%02d.%02d hours" % (duration / 60**2, duration % 60**2 / 60, duration % 60)
        # minutes
        return "%02d:%02d min" % (duration / 60, duration % 60)

    @property
    def hostnames(self):
        # Resolve the IPs of this flows to their hostname
        src_hostname = socket.getfqdn(self.src.compressed)
        dest_hostname = socket.getfqdn(self.dest.compressed)

        return Pair(src_hostname, dest_hostname)

    @property
    def service(self):
        # Resolve ports to their services, if known
        service = "unknown"
        try:
            # Try service of sending peer first
            service = socket.getservbyport(self.src_port)
        except OSError:
            # Resolving the sport did not work, trying dport
            try:
                service = socket.getservbyport(self.dest_port)
            except OSError:
                pass
        return service


# Handle CLI args and load the data dump
if len(sys.argv) < 2:
    exit("In correct usage of the PwC:(NetHunt™) Analysis tool. Please use as {} <DateStamp>.json".format(sys.argv[0]))
filename = sys.argv[1]
if not os.path.exists(filename):
    exit("File {} does not exist!".format(filename))
with open(filename, 'r') as fh:
    data = json.loads(fh.read())
    #print (data)


# Go through data and disect every flow saved inside the dump
for export in sorted(data):
    timestamp = datetime.fromtimestamp(float(export)).strftime("%Y-%m-%d %H:%M.%S")

    flows = data[export]
    #print (type(flows))
    pending = None  # Two flows normally appear together for duplex connection
    for flow in flows:
        if not pending:
            pending = flow
            #print ("Inside Not Pending")
        else:
            #print ("Attempting a connection")
            con = Connection(pending, flow)
            #print (con.size)
            print("{timestamp}: {service:7} | {size:8} | {duration:9} | {src_host} ({src}) to"\
                    " {dest_host} ({dest})".format(
                    timestamp=timestamp, service=con.service.upper(),
                    src_host=con.hostnames.src, src=con.src,
                    dest_host=con.hostnames.dest, dest=con.dest,
                    size=con.human_size, duration=con.human_duration))
            pending = None
            
