# Network Forensics PCAP Analysis 
## By Curtis Harris

# Executive Summary

According to my findings, a compromised pc was being used as a method to reach out to a suspicious website known as whitepepper.su which would then loop back any information to the network while bypassing any traffic that would be caught by the firewall. The potential impact is major and needs to be addressed immediately. The severity would be a mission critical level scenario where the affected PCs and systems need to be taken offline and quarantined while making adjustments to block traffic to the specific domain listed above and associated ips that are related. Given the nature of what was observed, the potential impact for business could be loss of company data, potential shut down of the network and complete compromise of sensitive user data given the Enterprise Level System running here. 

## Environment Overview

### Devices:

Intel Based Router
Intel_c8:0e:f2 mac (00:21:5d:c8:0e:f2) 
ips: 10.1.21.1 and 10.1.21.58


Server:
Dell_2d:ce:69 mac (14:b3:1f:2d:ce:69) 
Ip 10.1.21.2

Firewall solution 
Cisco_be:8c:d4 mac (00:04:c1:be:8c:d4)
ip: 10.1.21.1/ 10.1.21.2

Workstations:
DESKTOP-ES9F3ML ip address: 169.254.227.202
WIN11OFFICE ip address: 169.254.227.202
WIN-LU4L24X3UB7 ip address: 10.9.42.2

Given the configuration of the systems listed above there are overlapping ips between what I would consider the intel based router and the dell based server which I believe lead to a man in the middle attack given results from the pcap file provided. 





