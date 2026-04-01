# Simple Log Analyzer.py
# Designed to read files and identify repeated failed login attempts
# Will also Identify suspicious IP activity, identify privilege escalation attempts
# Code:You Cybersecurity Analyst Pathway 2025


from collections import Counter
filename = 'sample_log.txt'


event_counts = Counter()
user_counts = Counter()
ip_counts = Counter()
# Creating a counter auth success and auth failure.
auth_success = 0
auth_fail = 0

# Added lists to store details about failed logins and privilege changes for later review.
failed_logins = [] # store a few details about failures
priv_change = [] # store details about privilege changes

with open(filename, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue

        parts = line.split(None, 2)
        timestamp = parts[0]
        event = parts[1]
        rest = parts[2] if len(parts) > 2 else ""

        event_counts[event] += 1

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
        if event in ("AUTH_FAIL"):
            auth_fail += 1
            failed_logins.append((timestamp, user, ip, message))

        # Added for privilege change events
        if event == "PRIV_CHANGE":
            priv_change.append((timestamp, user, ip, message))

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

with open("summary.txt", "w", encoding="utf-8") as out: # Writing results to a file for review.

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

    if not failed_logins:
        write("No failed login attempts found.")
    else:
        write("\nDetails ):")
        for ts, user, ip, msg in failed_logins[:10]:
            write(f" {ts} user={user} ip={ip} message={msg}")    # Suspicious Privilege Changes
    
    write("\n=== Suspicious Privilege Changes ===")
    write(f"Total privilege change events: {len(priv_change)}")
    write(f"Suspicious events detected: {len(suspicious_priv)}")

    if not suspicious_priv:
        write("No suspicious privilege changes found.")
    else:
        write("\nDetails (up to first 10):")
        for ts, user, ip, msg in suspicious_priv:
            write(f" {ts} user={user} ip={ip} message={msg}")
    

