import re
import csv
import argparse
from collections import Counter

# Function to process the log file and extract useful information
def process_log_file(log_file):
    ip_counter = Counter()
    endpoint_counter = Counter()
    failed_login_attempts = Counter()

    # Define regex pattern for log entries (IP, method, endpoint, status code)
    log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s-\s\[\S+\s\S+\]\s"(?P<method>\S+)\s(?P<endpoint>\S+)\s\S+"\s(?P<status_code>\d+)\s\d+(\s"[^"]+")?'
    
    # Define regex pattern for failed login attempts (status 401 or "Invalid credentials" message)
    failed_login_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"Invalid credentials"'

    with open(log_file, 'r') as file:
        for line in file:
            # Count IP requests and endpoints
            log_match = re.match(log_pattern, line)
            if log_match:
                ip = log_match.group('ip')
                endpoint = log_match.group('endpoint')
                status_code = log_match.group('status_code')
                
                ip_counter[ip] += 1
                endpoint_counter[endpoint] += 1

                # Detect failed login attempts (status 401 or "Invalid credentials")
                if status_code == "401" or re.search(failed_login_pattern, line):
                    failed_login_attempts[ip] += 1

    return ip_counter, endpoint_counter, failed_login_attempts

# Function to identify the most accessed endpoint
def get_most_accessed_endpoint(endpoint_counter):
    if endpoint_counter:
        return endpoint_counter.most_common(1)[0]
    return None, 0

# Function to detect suspicious activity based on failed login attempts
def detect_suspicious_activity(failed_logins, threshold=10):
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

# Function to save the results to CSV file
def save_results_to_csv(ip_counter, most_accessed_endpoint, suspicious_ips):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Request Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        # Writing IP request counts
        writer.writeheader()
        for ip, count in ip_counter.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})

        # Writing Most Accessed Endpoint
        endpoint_name, endpoint_count = most_accessed_endpoint
        writer.writerow({'IP Address': 'Most Accessed Endpoint', 'Request Count': endpoint_name if most_accessed_endpoint else 'N/A'})
        writer.writerow({'IP Address': 'Access Count', 'Request Count': endpoint_count if most_accessed_endpoint else '0'})

        # Writing Suspicious Activity
        if suspicious_ips:
            writer.writerow({'IP Address': 'Suspicious Activity Detected', 'Request Count': 'Failed Login Attempts'})
            for ip, count in suspicious_ips.items():
                writer.writerow({'IP Address': ip, 'Request Count': count})
        else:
            writer.writerow({'IP Address': 'Suspicious Activity Detected', 'Request Count': 'None'})

# Function to display results on the console
def display_results(ip_counter, most_accessed_endpoint, suspicious_ips):
    # Display IP request counts
    print("IP Address           Request Count")
    for ip, count in ip_counter.most_common():
        print(f"{ip:<20}{count}")

    # Display Most Accessed Endpoint
    if most_accessed_endpoint:
        print(f"\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Display Suspicious Activity
    if suspicious_ips:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count}")

def main():
    # Set up argument parser for dynamic input
    parser = argparse.ArgumentParser(description="Analyze log file for IP requests, endpoints, and suspicious activity.")
    parser.add_argument('log_file', type=str, help="The path to the log file to be processed.")
    parser.add_argument('--threshold', type=int, default=10, help="The threshold for failed login attempts to flag as suspicious activity.")
    
    # Parse the command-line arguments
    args = parser.parse_args()
    
    # Process the log file
    ip_counter, endpoint_counter, failed_logins = process_log_file(args.log_file)

    # Identify the most accessed endpoint
    most_accessed_endpoint = get_most_accessed_endpoint(endpoint_counter)

    # Detect suspicious activity based on failed login attempts
    suspicious_ips = detect_suspicious_activity(failed_logins, args.threshold)

    # Display the results in the terminal
    display_results(ip_counter, most_accessed_endpoint, suspicious_ips)

    # Save the results to a CSV file
    save_results_to_csv(ip_counter, most_accessed_endpoint, suspicious_ips)

if __name__ == '__main__':
    main()
