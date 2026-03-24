# Simple Log Analyzer.py
# Designed to read files and identify repeated failed login attempts
# Will also Identify suspicious IP activity, identify privilege escalation attempts
# Code:You Cybersecurity Analyst Pathway 2025


from collections import Counter
filename = 'sample_log.txt'


event_counts = Counter()
user_counts = Counter()
ip_counts = Counter()

auth_success = 0
auth_fail = 0
failed_logins = [] # store a few details about failures

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



        if event == "AUTH_SUCCESS":
            auth_success += 1
        if event in ("AUTH_FAIL"):
            auth_fail += 1
            failed_logins.append((timestamp, user, ip, message))

# Print results

print("=== Summary ===")
print("Total Lines (events) by type:")
for ev, count in event_counts.most_common():
    print(f" {ev}: {count}")

print("\nTop 5 users:")
for user, count in user_counts.most_common(5):
    print(f"  {user}: {count}")

print("\nTop 5 IPs:")
for ip, count in ip_counts.most_common(5):
    print(f"  {ip}: {count}")

print("\nFirst 5 failed logins (if any):")
for item in failed_logins[:5]:
    ts, user, ip, msg = item
    print(f"  {ts} user={user} ip={ip} message={msg}")



        
        