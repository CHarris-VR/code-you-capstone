# Simple Log Analyzer.py
# Designed to read files and identify repeated failed login attempts
# Will also Identify suspicious IP activity, identify privilege escalation attempts
# Code:You Cybersecurity Analyst Pathway 2025
# Code was created in Python 3.11.5 incase of compatibility issues with older and newer versions.
# By Curtis Harris

# This code reads a log file, counts events, users, and IPs, 
# and identifies failed login attempts and suspicious privilege changes. 
# It then prints a summary to the console and writes details to a summary.txt file for review.
from collections import Counter

# Define the log file to analyze. 
# In a real scenario, this could be passed as an argument or read from a config.
filename = 'sample_log.txt'


event_counts = Counter()
user_counts = Counter()
ip_counts = Counter()
failed_user_login = Counter()

# Creating a counter auth success and auth failure.
auth_success = 0
auth_fail = 0

# Added lists to store details about failed logins and privilege changes for later review.
failed_logins = [] # store a few details about failures
priv_change = [] # store details about privilege changes

with open(filename, 'r', encoding='utf-8') as f:
    for line in f:
        # what does strip do? 
        # It removes leading and trailing whitespace, including newlines. 
        # This helps clean up the log lines for easier parsing.
        line = line.strip()
        if not line:
            continue

        # Basic parsing of log lines. This assumes a format like: 
        # "timestamp event user=... ip=... message=..."
        parts = line.split(None, 2)
        timestamp = parts[0]
        event = parts[1]

        # The rest of the line may contain user, ip, 
        # and message details. We will parse those if they exist.
        rest = parts[2] if len(parts) > 2 else ""

        event_counts[event] += 1

        # Initialize variables to store user, ip, and message details for this log line.
        user = ""
        ip = ""
        message = ""

        if "user=" in rest:
            user = rest.split("user=", 1)[1].split()[0]
            user_counts[user] += 1 
        
        if "ip=" in rest:
            ip = rest.split("ip=", 1)[1].split()[0]
            ip_counts[ip] += 1
        
        if "message=" in rest:
            message = rest.split("message=", 1)[1].strip()


        # Tests for Auth success token and auth fail token, and counts them, also stores details about 
        # failures for later review
        if event == "AUTH_SUCCESS":
            auth_success += 1
        if event == ("AUTH_FAIL"):
            auth_fail += 1
            failed_logins.append((timestamp, user, ip, message))
            failed_user_login[user] += 1


        # Added for privilege change events
        if event == "PRIV_CHANGE":
            priv_change.append((timestamp, user, ip, message))

# Repeated login attempts by user.
repeated_failed_users = {
    user: count for user, count in failed_user_login.items() if count > 1
}

# Added code to identify suspicious privilege changes based on keywords in the message
suspicious_priv = []

keywords = ("admin", "root", "sudo", "elevated")

for ts, user, ip, msg in priv_change:
    msg_lower = msg.lower()
    if any(k in msg_lower for k in keywords):
        suspicious_priv.append((ts, user, ip, msg))

# Print results to check code for correct functionality. 
print("=== Summary ===")
print("Total Lines (events) by type:")
for ev, count in event_counts.most_common():
    print(f" {ev}: {count}")

print("\nTop 10 Users:")
for user, count in user_counts.most_common(10):
    print(f"  {user}: {count}")

print("\nTop 5 IPs:")
for ip, count in ip_counts.most_common(5):
    print(f"  {ip}: {count}")

print("\nFirst 5 failed logins (if any):")
for item in failed_logins[:5]:
    ts, user, ip, msg = item
    print(f"  {ts} user={user} ip={ip} message={msg}")

print("\nFirst 5 privilege changes (if any):")
for item in priv_change[:5]:
    ts, user, ip, msg = item
    print(f"  {ts} user={user} ip={ip} message={msg}")    

print("\nFirst 5 suspicious privilege changes (if any):")
for item in suspicious_priv[:5]:
    ts, user, ip, msg = item
    print(f"  {ts} user={user} ip={ip} message={msg}")  

# Printing summary of repeated failed login attempts by user, sorted by count. This can help identify 
# potential brute-force attacks or compromised accounts.
print("\nRepeated failed login attempts by user:")
if not repeated_failed_users:
    print(" None found.")
else:
    for user, count in sorted(repeated_failed_users.items(), key=lambda x: x[1], reverse=True):
        print(f"  {user}: {count} failed logins")  

# Writing results to a file for review. This allows for a more permanent record 
# of the analysis and can be shared with others or used for further investigation.
with open("summary.txt", "w", encoding="utf-8") as out: 

    # Define a helper function to write lines to both the console and the file. 
    def write(line=""):
        print(line)
        out.write(line + "\n")

    write("=== Summary ===")


    # Authentication Successes
    write("\n=== Authentication Successes ===")
    write(f"Total successful logins: {auth_success}")
    
    # Authentication Failures
    write("\n=== Authentication Failures ===")
    write(f"Total failed logins: {auth_fail}")

    # Repeated Failed Logins. Added for log review.
    write("\n=== Repeated Failed Logins by User ===")
    if not repeated_failed_users:
        write("No repeated failed login attempts found.")
    else:
        for user, count in sorted(repeated_failed_users.items(), key=lambda x: x[1], reverse=True):
            write(f" {user}: {count} failed logins")

    if not failed_logins:
        write("No failed login attempts found.")
    else:
        write("\nDetails (First 10 failed logins.):")
        for ts, user, ip, msg in failed_logins[:10]:
            write(f" {ts} user={user} ip={ip} message={msg}")
    
    # Suspicious Privilege Changes
    write("\n=== Suspicious Privilege Changes ===")
    write(f"Total privilege change events: {len(priv_change)}")
    write(f"Suspicious events detected: {len(suspicious_priv)}")

    if not suspicious_priv:
        write("No suspicious privilege changes found.")
    else:
        write("\nDetails (All suspicious privilege changes.):")
        for ts, user, ip, msg in suspicious_priv:
            write(f" {ts} user={user} ip={ip} message={msg}")
    

