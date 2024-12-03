import re
import csv
from collections import Counter
from typing import List, Tuple

def analyze_ip_requests(log_file_path: str) -> List[Tuple[str, int]]:
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_counter = Counter()

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group()
                ip_counter[ip] += 1

    return sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)

def identify_most_accessed_endpoint(log_file_path: str) -> Tuple[str, int]:
    endpoint_pattern = r'\"(?:GET|POST|PUT|DELETE) (\S+) HTTP\/'
    endpoint_counter = Counter()

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_counter[endpoint] += 1

    if endpoint_counter:
        most_accessed = max(endpoint_counter.items(), key=lambda x: x[1])
        return most_accessed
    return ("No endpoints found", 0)

def detect_suspicious_activity(log_file_path: str, threshold: int) -> List[Tuple[str, int]]:
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    failed_login_pattern = r'401|invalid credentials'  
    failed_login_counter = Counter()

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            if re.search(failed_login_pattern, line, re.IGNORECASE):
                ip_match = re.search(ip_pattern, line)
                if ip_match:
                    ip = ip_match.group()
                    failed_login_counter[ip] += 1

    suspicious_ips = [(ip, count) for ip, count in failed_login_counter.items() if count >= threshold]
    return suspicious_ips

def save_to_csv(file_path: str, ip_requests: List[Tuple[str, int]], most_accessed: Tuple[str, int], suspicious_ips: List[Tuple[str, int]]):
    with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
        csv_file.write("Requests per IP:\n")
        csv_file.write("IP Address          Request Count      \n")
        for ip, count in ip_requests:
            csv_file.write(f"{ip.ljust(20)} {str(count).ljust(20)}\n")
        csv_file.write("\n")  


        csv_file.write("Most Accessed Endpoint:\n")
        csv_file.write("Endpoint             Access Count        \n")
        csv_file.write(f"{most_accessed[0].ljust(20)} {str(most_accessed[1]).ljust(20)}\n")
        csv_file.write("\n")  


        csv_file.write("Suspicious Activity:\n")
        csv_file.write("IP Address          Failed Login Count   \n")
        if suspicious_ips:
            for ip, count in suspicious_ips:
                csv_file.write(f"{ip.ljust(20)} {str(count).ljust(20)}\n")
        else:
            csv_file.write("No suspicious activity detected.\n")

def main():
    log_file_path = 'sample.log'
    csv_file_path = 'log_analysis_results.csv'


    ip_requests = analyze_ip_requests(log_file_path)
    print("Requests per IP:")
    print("IP Address          Request Count")
    for ip, count in ip_requests:
        print(f"{ip:<20}{count}")
    print()


    most_accessed = identify_most_accessed_endpoint(log_file_path)
    print("Most Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    print()


    suspicious_ips = detect_suspicious_activity(log_file_path, threshold=10)
    print("Suspicious Activity:")
    print("IP Address          Failed Login Count")
    if suspicious_ips:
        for ip, count in suspicious_ips:
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")
    print()


    save_to_csv(csv_file_path, ip_requests, most_accessed, suspicious_ips)
 

if __name__ == "__main__":
    main()
