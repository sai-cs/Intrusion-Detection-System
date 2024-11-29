import argparse
import re
import json
from collections import defaultdict
import csv
from datetime import datetime, timedelta

# Static IP data for enrichment (example data for demonstration purposes)
STATIC_IP_DATA = {
    "192.168.1.1": {"city": "Local", "region": "LAN", "country": "N/A", "org": "Private Network"},
    "8.8.8.8": {"city": "Mountain View", "region": "California", "country": "US", "org": "Google LLC"}
}

# Reads the log file and returns its content as a list of lines
def parse_logs(file_path):
    logs = []
    try:
        with open(file_path, 'r') as file:
            logs = [line.strip() for line in file]  # Remove whitespace and store each line
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")  # Notify the user if the file is missing
        exit(1)
    return logs

# Detects brute force attacks by counting failed login attempts per IP
def detect_brute_force(logs, threshold):
    failed_logins = defaultdict(int)  # Tracks failed login counts for each IP
    alerts = []

    for log in logs:
        # Match logs with failed login attempts and extract the IP
        match = re.search(r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)", log)
        if match:
            ip = match.group('ip')
            failed_logins[ip] += 1
            if failed_logins[ip] >= threshold:  # Trigger alert if the threshold is met
                alerts.append(f"Brute force detected: {ip} with {failed_logins[ip]} failed attempts.")
    return alerts

# Detects brute force attacks within a specific time window (e.g., 5 minutes)
def detect_time_based_brute_force(logs, threshold, time_window):
    failed_logins = defaultdict(list)  # Tracks timestamps of failed logins per IP
    alerts = []

    for log in logs:
        # Match logs with failed login attempts and extract timestamp and IP
        match = re.search(r"(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .* Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)", log)
        if match:
            ip = match.group('ip')
            timestamp = datetime.strptime(match.group('timestamp'), "%b %d %H:%M:%S")
            failed_logins[ip].append(timestamp)

            # Filter recent failures within the given time window
            recent_failures = [t for t in failed_logins[ip] if t > timestamp - timedelta(minutes=time_window)]
            if len(recent_failures) >= threshold:
                alerts.append(f"Time-based brute force detected: {ip} with {len(recent_failures)} failed attempts in the last {time_window} minutes.")
    return alerts

# Flags suspicious IPs provided by the user
def flag_suspicious_ips(logs, suspicious_ips):
    alerts = []
    flagged_ips = set()  # Ensures each suspicious IP is flagged only once

    for log in logs:
        # Extract IPs from the logs
        match = re.search(r"from (?P<ip>\d+\.\d+\.\d+\.\d+)", log)
        if match:
            ip = match.group('ip')
            if ip in suspicious_ips and ip not in flagged_ips:
                alerts.append(f"Suspicious activity detected from IP: {ip}.")
                flagged_ips.add(ip)  # Avoid duplicate alerts for the same IP
    return alerts

# Enriches IP details using the static IP data or defaults to "Unknown"
def enrich_ip_details(ip):
    return STATIC_IP_DATA.get(ip, {
        "ip": ip,
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "org": "Unknown"
    })

# Processes alerts to extract unique IPs and enrich them with metadata
def process_alerts(alerts):
    enriched_alerts = []
    seen_ips = set()
    for alert in alerts:
        ip = re.search(r"\b\d+\.\d+\.\d+\.\d+\b", alert).group(0)  # Extract IPs from alert text
        if ip not in seen_ips:  # Skip duplicate IPs
            seen_ips.add(ip)
            enriched_alerts.append(enrich_ip_details(ip))
    return enriched_alerts

# Saves enriched alerts to a JSON file
def save_alerts_to_file(enriched_alerts, output_file):
    with open(output_file, 'w') as file:
        json.dump(enriched_alerts, file, indent=4)
    print(f"Alerts saved to {output_file}")

# Saves enriched alerts to a CSV file
def save_alerts_to_csv(enriched_alerts, output_file):
    with open(output_file, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["ip", "city", "region", "country", "org"])
        writer.writeheader()
        writer.writerows(enriched_alerts)
    print(f"Alerts saved to {output_file}")

# Main function orchestrates the overall detection and alerting process
def main():
    parser = argparse.ArgumentParser(description="Intrusion Detection System (IDS) with Log Analysis.")
    parser.add_argument('log_file', help="Path to the log file to analyze.")
    parser.add_argument('--threshold', type=int, default=5, help="Threshold for failed login attempts to detect brute force (default: 5).")
    parser.add_argument('--time_window', type=int, default=5, help="Time window in minutes for time-based brute force detection (default: 5).")
    parser.add_argument('--suspicious_ips', nargs='*', default=[], help="List of suspicious IPs to flag.")
    parser.add_argument('--output', default='alerts.json', help="File to save the alerts (default: alerts.json).")

    args = parser.parse_args()

    # Step 1: Parse logs from the provided file
    logs = parse_logs(args.log_file)

    # Step 2: Run detection algorithms
    brute_force_alerts = detect_brute_force(logs, args.threshold)
    time_based_alerts = detect_time_based_brute_force(logs, args.threshold, args.time_window)
    suspicious_ip_alerts = flag_suspicious_ips(logs, args.suspicious_ips)

    # Combine all alerts
    all_alerts = brute_force_alerts + time_based_alerts + suspicious_ip_alerts

    # Step 3: Process and output the alerts
    if all_alerts:
        for alert in all_alerts:
            print(alert)
        enriched_alerts = process_alerts(all_alerts)
        if args.output.endswith('.json'):
            save_alerts_to_file(enriched_alerts, args.output)
        elif args.output.endswith('.csv'):
            save_alerts_to_csv(enriched_alerts, args.output)
        else:
            print("Unsupported output format. Use .json or .csv.")
    else:
        print("No suspicious activity detected.")

if __name__ == "__main__":
    main()
