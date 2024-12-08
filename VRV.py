import re
import csv
from collections import defaultdict

# Constants
LOG_FILE = 'sample.log'
OUTPUT_CSV = 'log_analysis_results.csv'
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Parse the log file and return a list of entries."""
    with open(file_path, 'r') as file:
        log_entries = file.readlines()
    return log_entries

def count_requests_per_ip(log_entries):
    """Count the number of requests made by each IP address."""
    ip_count = defaultdict(int)
    for entry in log_entries:
        ip_address = entry.split()[0]
        ip_count[ip_address] += 1
    return dict(ip_count)

def identify_most_accessed_endpoint(log_entries):
    """Identify the most frequently accessed endpoint."""
    endpoint_count = defaultdict(int)
    for entry in log_entries:
        # Extract the endpoint using regex
        match = re.search(r'\"[A-Z]+\s+([^ ]+)', entry)
        if match:
            endpoint = match.group(1)
            endpoint_count[endpoint] += 1
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1])
    return most_accessed

def detect_suspicious_activity(log_entries):
    """Detect suspicious activity based on failed login attempts."""
    failed_login_count = defaultdict(int)
    for entry in log_entries:
        if '401' in entry or 'Invalid credentials' in entry:
            ip_address = entry.split()[0]
            failed_login_count[ip_address] += 1
    # Filter IPs exceeding the threshold
    suspicious_ips = {ip: count for ip, count in failed_login_count.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

def save_results_to_csv(ip_counts, most_accessed, suspicious_activity):
    """Save the results to a CSV file."""
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        
        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])
        
        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    log_entries = parse_log_file(LOG_FILE)

    # Analyze log data
    ip_counts = count_requests_per_ip(log_entries)
    most_accessed_endpoint = identify_most_accessed_endpoint(log_entries)
    suspicious_activity = detect_suspicious_activity(log_entries)

    # Display results
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV
    save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity)

if __name__ == "__main__":
    main()