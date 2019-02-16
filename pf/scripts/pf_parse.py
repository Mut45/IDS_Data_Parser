import re
import os
import config
def get_rules_test(line):
    rules_set = {}
    rule = line.rstrip('\n')
    rule_match = re.match( r'\@(\d+) (\w+.*)' #time
            ,rule)
    rules_set[rule_match.group(1)] = rule_match.group(2)
    print rules_set
    

# Read the rule set of PF and outputs a dictionary containing those rules
def get_rules_from_system():
    log_data = os.popen('pfctl -vvsr | grep @').read()
    rules_set = {}
    for line in log_data:
        rule = line.rstrip('\n')
        rule_match = re.match( r'\@(\d+) (\w+.*)' #time
            ,rule)
        rules_set[rule_match.group(1)] = rule_match.group(2)
    return rules_set
        
        
        

# Use the tcpdump to parse the pflog file and outputs it as a popen object
def get_log_from_system():
    try:
        pflog_path = "tcpdump -neltttr" + config.config['PFLOG_PATH']
        log_data = os.popen(pflog_path)
        return log_data
    except:
        return "null"

def parse_pf_data_test(log_data):
    for line in log_data:
        if "reassembly time exceeded" in line:
            continue
        if "multicast listener report" in line:
            continue
        if "tcpdump" in line:
            continue
        if "cookie:" in line:
            continue
        if "source quench" in line:
            continue
        if "igmp" in line:
            continue
        if re.search(r'at-\#',line):
            continue
        if re.search('icmp6', line, re.IGNORECASE): # ICMP6 
            if "who has" in line:
                continue
            matchobj = re.match(r'(\w+ \d+ \d+:.\d:.\d+)\.(\d+) rule (\d+)\/\(match\) (\w+ \w+) \w+ (\w+)\: ([a-f0-9\:]+) > ([a-f0-9\:]+).*',line)
        elif re.search('ip6', line, re.IGNORECASE) and re.search('encap', line, re.IGNORECASE): # IPv6 Encapsulation Agent
            matchobj = re.match(r'((\w+ \d+ \d+:.\d:.\d+)\.(\d+) rule (\d+)\/\(match\) (\w+ \w+) \w+ (\w+)\: .*',line)  
        elif re.search('gre encap'): # Generic Routing Encapsulation
            matchobj = re.match(r'(\w+ \d+ \d+:.\d:.\d+)\.(\d+) rule (\d+)\/\(match\) (\w+ \w+) \w+ (\w+)\: .*',line)
    print matchobj.group(1)

def parse_pf_data():
    log_data = ""
    if get_log_from_system() == "null":
        log_data_name = input("Enter the name of the pf log file to be parsed:")
        log_data = open(log_data_name)
    else:
        log_data = get_log_from_system()

    for line in log_data:
        continue if "reassembly time exceeded" in line
        continue if "multicast listener report" in line
        continue if "tcpdump" in line
        continue if "cookie:" in line
        continue if "source quench" in line
        continue if "igmp" in line
        continue if re.search(r'at-\#',line)
        if re.search('icmp6', line, re.IGNORECASE) # ICMP6 
            continue if "who has" in line
            matchobj = re.match(r'(\w+ \d+ \d+:.\d:.\d+)\.(\d+) rule (\d+)\/\(match\) (\w+ \w+) \w+ (\w+)\: ([a-f0-9\:]+) > ([a-f0-9\:]+).*',line)
        elif re.search('ip6', line, re.IGNORECASE) and re.search('encap', line, re.IGNORECASE): # IPv6 Encapsulation Agent
            matchobj = re.match(r'((\w+ \d+ \d+:.\d:.\d+)\.(\d+) rule (\d+)\/\(match\) (\w+ \w+) \w+ (\w+)\: .*',line)  
        elif re.search('gre encap'): # Generic Routing Encapsulation
            matchobj = re.match(r'(\w+ \d+ \d+:.\d:.\d+)\.(\d+) rule (\d+)\/\(match\) (\w+ \w+) \w+ (\w+)\: .*',line)
                


    
# Test cases
#get_rules_test('@1 pass in log proto tcp from any to any port = ldaps flags S/SA keep state')

#test cases for parse_pf_data
parse_pf_data_test(" 00:00:00.000185 rule 0/0(match): block in on em0: fe80::c4f:2e96:d24e:5364 > ff02::16: HBH ICMP6, multicast listener report v2[|icmp6], length 28")

    
