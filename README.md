
# Intrusion Detection System

A lightweight Python-based tool for analyzing server logs, detecting brute force attacks, and identifying suspicious IPs. This project demonstrates core concepts in **network security** and log analysis.

## Features
- Detects **brute force attacks** with a customizable threshold.
- Flags **suspicious IPs** and enriches alerts with metadata (e.g., location, organization).
- Supports **time-based detection** within a configurable time window.
- Outputs results in **JSON** or **CSV** formats.

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/ids.git
   cd ids
   ```

2. Run the script:
   ```bash
   python ids.py <log_file> --threshold <failed_attempts_threshold> --time_window <time_window_minutes> --suspicious_ips <ip1> <ip2> ... --output <output_file>
   ```
   Example:
   ```bash
   python ids.py sample_logs.txt --threshold 3 --time_window 5 --suspicious_ips 192.168.1.1 --output alerts.json
   ```

## Files
- **`ids.py`**: Main script for intrusion detection.
- **`sample_logs.txt`**: Example log file for testing.

This project showcases:
- Practical skills in **network security** and **log analysis**.
- Implementation of **threat detection** and **incident response** strategies.

---

## Disclaimer
This Intrusion Detection System is an educational project created to showcase Network Security and Log Analysis skills. It is not intended for production use or to handle sensitive information.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

Feel free to explore, use, and modify this project for your learning and personal projects!
