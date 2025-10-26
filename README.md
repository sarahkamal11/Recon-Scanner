# Recon Scanner  

Python vulnerability recon tool that uses TCP port scanning, banner grabbing, basic CVE lookups, and JSON report generation.  
This project is intended for learning, demos, and authorized testing only.

**Features**  
TCP connect port scanning (supports port ranges)  
Banner grabbing for common services (HTTP, SSH, FTP, etc.)  
Concurrent scans using `ThreadPoolExecutor`  
Attempts CVE lookups via NVD when available  
JSON report output (example included)  

**Requirements**  
Python 3.8+

**Usage**  
`python3 scanner.py --target example.com --ports 22,80,443 --output report.json`  

`python3 scanner.py --target example.com --ports 1-1024 --threads 50 --output report.json`
