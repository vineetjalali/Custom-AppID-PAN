"""
This Python3 script parses a PCAP file and looks for recurring data patterns in TCP or UDP payloads.
These can then be used as signatures while building a custom App-ID.
It works for captures with multiple sessions/segments of the same unknown-tcp or udp traffic.
Intended to be used with context unknown-<req|rsp>-tcp-payload and unknown-<req|rsp>-udp-payload, but strings can be converted to ASCII and used in other contexts.
Requires the library dpkt (https://dpkt.readthedocs.io/en/latest/)

Usage: CustomAppID.py -<client|server> <pcap file>
       -client      analyses client traffic
       -server      analyses server traffic

Caveats:
-Only the first client or server payload in each TCP flow is considered for matching.
-The higher the number of conversations in the PCAP, the more accurate the results will be.
-TCP or UDP traffic in the PCAP must belong exclusively to the application being analysed.
-The script works with TCP-only or UDP-only PCAPs. Mixed protocols will result in unreliable output.
-The script finds repetitions in payloads. It does not verify that the strings found are specific enough not to overlap with
 other unknown TCP/UDP traffic. Always validate your findings.

Author: Lorenzo Castelletti
Email: lcastellet@paloaltonetworks.com

© 2020 Palo Alto Networks, Inc.  All rights reserved.
Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc.,
at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
"""

import dpkt
import sys
import datetime
import re
from collections import Counter

lengths = {}
tomatch = []
globalmatch = []
seqlist = []
strings = {}
complete = 1
tcpcounter = 0
ipcounter = 0
udpcounter = 0
iteration = 0
srvport = 0
seq = 0

# Function that calculates the longest match given a set of strings. Credits: https://tinyurl.com/v2sr4d5
def long_substr(data):
    substr = ''
    if len(data) > 1 and len(data[0]) > 0:
        for i in range(len(data[0])):
            for j in range(len(data[0])-i+1):
                if j > len(substr) and all(data[0][i:i+j] in x for x in data):
                    substr = data[0][i:i+j]
    return substr

# This function populates a dictionary of frequency of payload lengths and a dictionary of payloads and their lengths
def pktprocessing(length):
    payload = bytes.hex(l4.data)
    if length in lengths:
        lengths[length] += 1
    else:
        lengths[length] = 1
    strings[payload] = length

try:
    file = open(sys.argv[2], 'rb')
    if sys.argv[1] == '-client':
        direction = 0
    if sys.argv[1] == '-server':
        direction = 16
except:
    print('Usage: CustomAppID.py -<client|server> <pcap file>')
    print()
    print('-client      analyses client traffic')
    print('-server      analyses server traffic')
    quit()
print('Start time:', datetime.datetime.now().time())

# PCAP parsing starts here
for ts, pkt in dpkt.pcap.Reader(file):
    iteration += 1
file.seek(0)
for ts, pkt in dpkt.pcap.Reader(file):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    l4 = ip.data
    if ip.p==dpkt.ip.IP_PROTO_TCP:
        seq = l4.seq
    ipcounter += 1
    print ('Processing IP packet', ipcounter, 'of', iteration, '- Percentage completed:', format(float(ipcounter*100/iteration), '.2f'), end='\r')
    # analyse flow when a TCP SYN is found. Ignore if the SYN is a re-transmission
    if ip.p==dpkt.ip.IP_PROTO_TCP and ( l4.flags & dpkt.tcp.TH_SYN ) != 0 and ( l4.flags & dpkt.tcp.TH_ACK ) == direction and seq not in seqlist:
        seqlist.append(seq)
        position = file.tell()
        file.seek(0)
        seekdone = 0
        # Look for initial payload for flow identified in previous loop
        for ts, pkt in dpkt.pcap.Reader(file):
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            l4 = ip.data
            if seekdone == 0:
                file.seek(position)
                seekdone = 1
            length = len(l4.data)
            # If payload is first in the flow, grab length and actual payload in HEX for comparison, then return to saved position
            if ip.p==dpkt.ip.IP_PROTO_TCP and length > 0 and l4.seq == seq + 1 and l4.seq not in seqlist:
                seqlist.append(l4.seq)
                pktprocessing(length)
                tcpcounter += 1
                file.seek(position)
                break
        file.seek(position)
    # Analyse layer 4 info if UDP
    if ip.p==dpkt.ip.IP_PROTO_UDP:
        if srvport == 0:
            srvport = input('This capture contains UDP packets. Please enter the UDP port the server listens on: ')
        length = len(l4.data)
        if length > 0 and (l4.dport == int(srvport) and direction == 0) or (l4.dport != int(srvport) and direction == 16):
            pktprocessing(length)
            udpcounter += 1
if tcpcounter == 0 and udpcounter == 0:
    complete = 0
filename=re.search("[A-Za-z0-9_-]+\.[A-Za-z0-9]+",sys.argv[2])
filename=filename.group()
f = open('output-'+filename+sys.argv[1]+'.txt','a')
readme = """
************ READ ME FIRST ************

This file is divided in four sections.

Section one.   Shows patterns found, ordered by payload length.
               Eg. All payloads with length X have in common pattern Y, etc.

Section two.   If more than one payload length is available, the script will try to find a common pattern across all lengths.
               If a global common pattern is available in section two, this is probably the best candidate for the signature.
               If a common pattern is not available, one should use all the strings found in section one, if possible.

Section three. This is to be used as a last resort if the second section does not show a global common pattern
               AND there are too many payload lengths in the first section.
               The recommended way to use data from section three is to recursively select the longest and most common patterns
               and remove from this file all the payload lengths containing the specified pattern. This will hopefully leave
               just a few payloads. These can be used, together with the patterns initially selected from section three, to
               generate OR conditions.

Counters.      Information on number of datagrams and segments analysed.

Please keep in mind the following caveats:

-Only the first client or server payload in each TCP flow is considered for matching.
-The higher the number of conversations in the PCAP, the more accurate the results will be.
-TCP or UDP traffic in the PCAP must belong exclusively to the application being analysed.
-The script works with TCP-only or UDP-only PCAPs. Mixed protocols will result in unreliable output.
-The script finds repetitions in payloads. It does not verify that the strings found are specific enough not to overlap with
 other unknown TCP/UDP traffic. Always validate your findings.

************* SECTION ONE *************
"""
print(readme, file=f)

# HEX strings matching starts here. Packets are first ordered by payload length
iteration = 0
for n in sorted(lengths):
    iteration += 1
    print('Finding repetitions in payloads. Hang on... - Percentage completed:', int(iteration*100/len(lengths)), end='\r')
    for index, value in strings.items():
        if value == n:
            tomatch.append(index)
    match = long_substr(tomatch)
    # Display common pattern for payloads of same length. Assuming that same length might equal to same functionality
    if match != '':
        print('', file=f)
        print(lengths[int(n)], 'payloads of', int(n), 'bytes. Pattern found:', match, file=f)
        if len(match)/2 < 7:
            complete = 0
            print('This string is shorter than 7 bytes. See below for all unique payloads', file=f)
            for x in tomatch:
                print(x, file=f)
        else:
            globalmatch.append(match)
    else:
        if len(tomatch) == 1:
            print('', file=f)
            print(lengths[int(n)], 'equal payload(s) of', int(n), 'bytes:', tomatch[0], file=f)
            globalmatch.append(tomatch[0])
        else:
            complete = 0
            print('', file=f)
            print(lengths[int(n)], 'payloads of', int(n), 'bytes. No pattern found. See below for all unique payloads', file=f)
            for x in tomatch:
                print(x, file=f)
    tomatch = []

# Display common pattern across payloads of different length. If available, this is probably the best candidate for our signature
print('', file=f)
print('************* SECTION TWO *************', file=f)
if complete == 1 and len(lengths) > 1:
    match = long_substr(globalmatch)
    print('', file=f)
    print('*** Global common substring across all payload sizes:', match, '***', file=f)
    print('', file=f)
    #print('ASCII conversion of the Global common substring:', file=f)
    #print(str(bytes.fromhex(match)), file=f)
    if len(match)/2 < 7:
        print('This string is shorter than 7 bytes. Use all previously found strings in section one or see section three if there are additional partial patterns', file=f)
elif len(lengths) > 1:
    print('', file=f)
    print('*** No global common substring found. Use all previously found strings in section one, if any, or see section three if there are additional partial patterns. ***', file=f)
print('', file=f)

# This section lists partial patterns to be used when previous results do not offer enough coverage or are impractical
print('************ SECTION THREE ************', file=f)
print('', file=f)
s = str(globalmatch)
for n in range(14, len(s)):
    subcount = Counter(s[i: i+n] for i in range(len(s) - n))
    pattern, count = subcount.most_common(1)[0]
    if count == 1:
        break
    print ('Bytes:', n/2, '- Occurrences:', count, '- Pattern:', pattern, file=f)

print('', file=f)
print('*************** COUNTERS **************', file=f)
print('', file=f)
print('Total number of TCP segments analysed for matches:', tcpcounter, '. A low number of sessions might produce incomplete results', file=f)
print('Total number of UDP segments analysed for matches:', udpcounter, '. A low number of segments might produce incomplete results', file=f)
print('Total number of analysed IP packets:', ipcounter, file=f)
print('Processing complete. Please open file output-'+filename+sys.argv[1]+'.txt in this folder for your findings.')
print('Finish time:', datetime.datetime.now().time())