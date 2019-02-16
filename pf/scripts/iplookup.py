from ipwhois import IPWhois
import socket


def ip_look_up(ip):
    ip_dict = {}
    try:
        ip_dict = IPWhois(ip).lookup_whois()
        ip_dict["private"] = "no"
        return ip_dict
    except:
        ip_dict["private"] = "yes"
        return ip_dict
def dns_look_up(dns):
    return ip_look_up(socket.gethostbyname(dns))
    
print ip_look_up(socket.gethostbyname('www.google.com'))