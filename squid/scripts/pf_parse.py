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


def parse_pf_data():
    log_data = ""
    if get_log_from_system() = "null":
        log_data_name = input("Enter the name of the pf log file to be parsed:")
        log_data = open(log_data_name)
    else:
        log_data = get_log_from_system()

    for line in log_data:
        continue if "tcpdump" in line
        continue if "cookie:" in line
        continue if "source quench" in line
        continue if "igmp" in line
        continue if "reassembly time exceeded" in line
        continue if "multicast listener report" in line
        continue if re.match(r'at-\#',line)
        line = line.rstrip('\n')
        if "icmp6" in line:
            continue if "who has" in line
            matchobj = re.match(r'(\w+ \d+ \d+:.\d:.\d+)\.(\d+) rule (\d+)\/\(match\) (\w+ \w+) \w+ (\w+)\: ([a-f0-9\:]+) > ([a-f0-9\:]+).*',line)
            


    
# Test cases
#get_rules_test('@1 pass in log proto tcp from any to any port = ldaps flags S/SA keep state')


    
