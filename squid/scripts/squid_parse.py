#tcpdump -n -e -ttt -r /var/log/pflog

#Each packet retrieved on this interface has a header associated with it
# of length PFLOG_HDRLEN.  This header documents the address family,
# interface name, rule number, reason, action, and direction of the packet
# that was logged.  This structure, defined in <net/if_pflog.h> looks like
#   /time, rule#, packet direction in/out, interface, source ip, dest ip,
# mss = maximum sequence size
# Flags = [S] = sync
# win = window size
# seq = sequence number
#       struct pfloghdr {
#               u_int8_t        length;
#               sa_family_t     af;
#               u_int8_t        action;
#               u_int8_t        reason;
#               char            ifname[IFNAMSIZ];
#               char            ruleset[PF_RULESET_NAME_SIZE];
#               u_int32_t       rulenr;
#               u_int32_t       subrulenr;
#               uid_t           uid;
#               pid_t           pid;
#               uid_t           rule_uid;
#               pid_t           rule_pid;
#               u_int8_t        dir;
#               u_int8_t        pad[3];
#       };
#/Users/johndale/Desktop/pf_parsing
import re
# line = " 00:00:00.000000 rule 5/0(match):"
line = " 00:00:00.000000"
#line = " 00:00:00.000000 rule 5/0(match): pass out on lo0: 127.0.0.1.13244 > 127.0.0.1.25: Flags [S], seq 4111352249, win 65535, options [mss 16344,nop,wscale 6,sackOK,TS[|tcp]>"
# line = " 00:00:00.013365 rule 3/0(match): pass in on em0: 10.53.12.251.64303 > 10.138.120.3.22: Flags [S], seq 3665560187, win 65535, options [mss 1386,nop,wscale 6,nop,nop,TS[|tcp]>"
# line= " 00:00:00.001348 rule 6/0(match): pass out on em0: 10.138.120.3.27451 > 10.48.88.2.53: 9340+[|domain]"
# line= " 00:00:00.000006 rule 0/0(match): block in on em0: fe80::9045:3cd4:9be0:9166.5353 > ff02::fb.5353: 0 PTR (QM)? _scanner._tcp.local. (37)"
# line=" 00:00:00.000001 rule 0/0(match): block in on bridge0: 10.138.120.4.8612 > 10.138.120.255.8610: UDP, length 16"
#line=" 00:00:00.022514 rule 0/0(match): block in on em0: fe80::9045:3cd4:9be0:9166 > ff02::16: HBH ICMP6, multicast listener report v2, 2 group record(s), length 48"
# matchObj = re.match( r'\s(\d+:.\d+:.\d+\.\d+)\s+' #time
#                     '(rule+\s+(\d+)\/\d+\(match\)\:)\s+' #rule # and match
#                     '(\w+\s\w+\s\w+)\s+' #action ex. pass in on
#                     '(\w+)\:\s+' # interface
#                     '(\d+\.\d+.\d+\.\d+)' #sourceIP
#                     '\.(\d+)\s+\>\s+' #sourcePort
#                     '(\d+\.\d+.\d+\.\d+)' #destIP
#                     '\.(\d+)\:\s+' #destPort
#                     '(.*)' #rest of line
#                     , line, re.M|re.I)
# matchObj = re.match( r'\s(\d+:.\d+:.\d+\.\d+)\s+' #time
#                     '(rule+\s+(\d+)\/\d+\(match\)\:)\s+' #rule # and match
#                     '(\w+\s\w+\s\w+)\s+' #action ex. pass in on
#                     '(\w+)\:\s' # interface
#                     '(.*?)\s'
#                     # '((.*?)\.[^\.]+$)' #sourceIP
#                     # '\.(\d+)\s+\>\s' #sourcePort
#                     # '(.*?)\.' #destIP
#                     # '(\d+)\:\s' #destPort
#                     # '(.*)' #rest of line
#                     , line, re.M|re.I)
matchobj = re.match( r'\s(\d+:.\d+:.\d+\.\d+)' #time
            ,line)

# matchobj = re.match(r'\s(\d+:\d+:\d+\.\d+)' #time
#             ,line)

# matchObj = re.match(r'.*', 'fe80::9045:3cd4:9be0:9166.52', re.M|re.I)
if matchobj:
   print(matchobj.group(1))
   print(matchobj.group(1)[0]==" ")
   #print("matchObj.group(1) : ", matchObj.group(1))
   # print("matchObj.group(2) : ", matchObj.group(2))
   # print("matchObj.group(3) : ", matchObj.group(3))
   # print("matchObj.group(4) : ", matchObj.group(4))
   # print("matchObj.group(5) : ", matchObj.group(5))
   # print("matchObj.group(6) : ", matchObj.group(6))
   # print("matchObj.group(7) : ", matchObj.group(7))
   # print("matchObj.group(8) : ", matchObj.group(8))
   # print("matchObj.group(9) : ", matchObj.group(9))
   # print("matchObj.group(1) : ", matchObj.group(10))
   # print("matchObj.group(8) : ", matchObj.group(8))
   # print("matchObj.group(9) : ", matchObj.group(9))
   # print("matchObj.group(10) : ", matchObj.group(10))
else:
   print("No match!!")
# import re
# import pandas as pd
# try:
#     with open('pflog_file copy.txt', 'r',encoding='utf-8') as file:
#         for line in file:
#             matchObj = re.match(r'\s(\d{2}:\d{2}:\d{2}\.\d+) rule (_)', line)
#             # s = line.match('\d')
#             print(matchObj.group(1))
#
#             # \s+(\d+)\/(\d+)\((\w+)\)\:\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\:\s+([\-\+]{0,1}\d[\d\.\,]*[\.\,][\d\.\,]*\d+)\s+\x{3E}\s+([\-\+]{0,1}\d[\d\.\,]*[\.\,][\d\.\,]*\d+)\:\s+(\w+)\s+\[(\w+)\]\,\s+(\w+)\s+(\d+)\,\s+(\w+)\s+(\d+)\,\s+(\w+)\s+\[(\w+)\s+(\d+)\,(\w+)\,(\w+)\s+(\d+)\,(\w+)\,(\w+)\[\|(tcp)\]\x{3E})")
#             # print(s)
#             #
#             # for k in s:
#             #     print(k)
#             # print()
#
#
#         # print(file_contents)
#         # s = re.split("(\s+(\d+)\:(\d+)\:([\-\+]{0,1}\d[\d\.\,]*[\.\,][\d\.\,]*\d+)\s+(\w+)\s+(\d+)\/(\d+)\((\w+)\)\:\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\:\s+([\-\+]{0,1}\d[\d\.\,]*[\.\,][\d\.\,]*\d+)\s+\x{3E}\s+([\-\+]{0,1}\d[\d\.\,]*[\.\,][\d\.\,]*\d+)\:\s+(\w+)\s+\[(\w+)\]\,\s+(\w+)\s+(\d+)\,\s+(\w+)\s+(\d+)\,\s+(\w+)\s+\[(\w+)\s+(\d+)\,(\w+)\,(\w+)\s+(\d+)\,(\w+)\,(\w+)\[\|(tcp)\]\x{3E})".encode("UTF-8"), file_contents )
#
# except IOError as err:
#     print ("Error reading the file {0}: {1}".format(file, err))
