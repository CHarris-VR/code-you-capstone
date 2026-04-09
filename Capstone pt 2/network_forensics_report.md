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

![image alt](https://github.com/CHarris-VR/code-you-capstone/blob/main/photos/refpic1.png)

## Host Identification

Host: DESKTOP-ES9F3ML
DNS Domain: win11office.com
Ip Address: 10.9.42.58

![image alt](https://github.com/CHarris-VR/code-you-capstone/blob/main/photos/refpic2.png)

## Traffic Analysis Findings

This is a method that I learned from a friend that he called “Hiding in plain-text(sight)” where sometimes you want to look for the most obvious to find the least obvious in a dataset. So using this filter I was immediately able to find some traffic that was incredibly weird, but just having a line of russian that translates to “Convert to URLSearchParams” doesn’t mean that this is inherently bad. 
Though given that our Enterprise doesn’t explicitly state that it communicates or talks with Russian based clients, this is a major concern in my opinion, sitting there in plain text. 
![image alt](https://github.com/CHarris-VR/code-you-capstone/blob/main/photos/refpic3.png)

Picture for reference of searching what the russian characters were using google lens and taking a screenshot of the specific line as a picture:
![image alt](https://github.com/CHarris-VR/code-you-capstone/blob/main/photos/refpic4.png)

And using the same filter we can see that the same conversation between 153.92.1.49 is also trying to send a zip file to address 10.1.21.58
![image alt](https://github.com/CHarris-VR/code-you-capstone/blob/main/photos/refpic5.png)

Now from here, I needed to figure out how to make the above make sense on why I believe this to be the Command and Control Center.

Here is a list of Wireshark filters used if pictures do not already show them:
Data-text-lines
ip.addr == 10.1.21.58
Frame contains “DESKTOP-”
frame contains “DESKTOP-ES9F3ML”
eth.addr eq 00:21:5d:c8:0e:f2 and eth.addr eq ff:ff:ff:ff:ff:ff
ip.addr == 10.9.42.58
frame contains "win11office.com"
frame contains “whitepepper.su”
tls and ip.addr == 153.92.1.49

### Suspicious Traffic Patterns

Given the above that 153.92.1.49 seems suspicious ip.addr == 153.92.1.49 was used to further investigate
![image alt](https://github.com/CHarris-VR/code-you-capstone/blob/main/photos/refpic6.png)

Given that specific investigation we can see that several calls are being made from this server that has tried to send suspicious HTTP packets to one of our home devices which seems odd but there’s nothing other than the HTTP packets that were discussed earlier so far. Which is where we get into our DNS analysis utilizing what we understand thus far.

## DNS Analysis 

Initial search on DNS returned something that was quite strange to me and lead me to a domain called win11office.com which doesn’t return any valid or legitimate service that I could see, also our server initially created a user named win11office at the beginning of our search so I decided to investigate the source host at 10.9.42.58
![image alt](https://github.com/CHarris-VR/code-you-capstone/blob/main/photos/refpic7.png)

Which lead to using the filter dns and ip.src_host == 10.9.42.58
![image alt](https://github.com/CHarris-VR/code-you-capstone/blob/main/photos/refpic8.png)

Investigated the whitepepper[.]su since that is linked to the Soviet Union.
Using dns.qry.name == whitepepper.su 
![image alt](https://github.com/CHarris-VR/code-you-capstone/blob/main/photos/refpic9.png)

Traffic from 10.9.42.2 our local pc that is sending data and receiving data 10.1.21.58 and 10.1.21.58 from a domain named whitepepper[.]su and referencing an ip 153.92.1.49 and can confirmed from earlier traffic analysis was sending strange packets in plain text.

## Command and Control (C2) Activity
Based on findings from traffic above and creation and registration of NB DESKTOP-ES9F3ML ips using the created desktop were sending strange out bound traffic
![image alt](https://github.com/CHarris-VR/code-you-capstone/blob/main/photos/refpic10.png)

![image alt](https://github.com/CHarris-VR/code-you-capstone/blob/main/photos/refpic11.png)

Which is indicated by the picture above showing several query responses that link to the earlier described website and sharing communication with the C2 center located at ip 153.92.49

The pattern that was recorded the most was Standard query reaching out to a whitepepper[.]su and referencing the 153.92.1.49 ip as if to try and hide the specific ip it was trying to communicate with and a payload was placed onto the destination ip of 10.1.21.58:

![image alt](https://github.com/CHarris-VR/code-you-capstone/blob/main/photos/refpic12.png)

## Indicators of Compromise (IOC)

Ip addresses:
10.1.21.58
10.9.42.58
153.92.1.49

Domains and URLs:
win11office.com
whitepepper.su


File artifacts:
172.56.88.98-038485b1855ec7ab5bbda042ad17a1.zip
Json.txt 

## Timeline of Activity

2026 - 1 - 28  4:04.06 | Registration of NB DESKTOP-ES9F3ML and WIN11OFFICE

2026 - 1 - 28 4:04.27 | Query response for wpad.win11office.com showed failure to port 49372

2026 - 1 - 28 05:36:21 | Query from white pepper.su response from 153.92.1.49

2026 - 1 - 28 05:39.57 | Query from 153.92.1.49 to 10.1.21.58 initial HTTP calls to send payload

2026 - 1 - 28 05:47.79 | Attempt to open archive .zip file through HTTP on Destination ip 10.1.21.58

Using pictures from above, the time stamps were converted to represent the proper human readable time stamps for when specific events happened. 

## Attack Narrative:

The likely sequence of events would be the initial infection regarding the registration of the NB Desktop-ES9F3ML. From there attackers were able to create query options for the win11office.com domain through the server to see what was communicating with which systems in the office was running on with the server. 

The attackers utilized a backdoor to get around the Cisco level router detection by utilizing a compromised computer system to then send query data to the whitepeper.su website and contact the C2 center at the 153.92.1.49 ip and proceed to send a payload zip to the compromised devices and affected ip at 10.1.21.58.

## Impact Assessment:

The Dell server and DESKTOP-ES9F3ML computer are affected. With this sort of attack the data on the server could be completely compromised as the attackers have shown that they are able to completely access the server and send and receive data from the server while trying to execute malicious zip files to be sent over the network to the affected server.  The organizational impact could lead to company wide shut down from data exfiltration leading to loss of company assets such as secrets, build plans and other assets depending on what data the affected server holds. 

## Recommendations:

### Immediate Actions:
- Block whitepepper.su and ip 153.92.1.49 from accessing the network by any means

- Disable DESKTOP-ES9F3ML from any and all communication with the internet and intranet as possible or remove access from specific ips limiting their networking access if the desktop is unable to be disconnected for any reason within the enterprise.

- Reset all and any associated passwords relative to the compromised pc’s credentials to prevent other anomalous attempts at reestablishing connection with the C2 center. 

### Short-Term improvements:

- Scan all endpoints for malware / viruses

- Make sure that all devices are up to date and have the current windows 11 security updates installed and implemented

- Monitor network for anomalous activity

### Long-Term Improvements:
- Ensure Endpoint Detection and Response (EDR) is being utilized

- Ensure proper ARP set up between communication devices (network router, firewall communication)

- Create faster methods to scan log data for events involving networks

- Lessons learned for the security and networking team to hopefully prevent further attacks from being as successful. 

## Reflection: 

This was a very challenging task to start off with given a short time frame however I believe that even though I didn’t probably hit everything I am happy with what I have learned, what I already knew and what methods I was able to discover and use to make this task something of a more fun than scary task to complete. The technique I used most when working on this project was thinking about what I needed, and not giving up and trying to find ways to locate the info I needed. There’s no way I could possibly remember all display filters, however using google I was able to find combos that lead to much better and stronger results to support my findings.

The things that I’d Improve on are writing down when and where I found specific data, it was difficult for me to specifically recall a time line of specific events completely from memory and pictures using different timeline data but at the end of the day I am happy with my project, my lessons learned 
















