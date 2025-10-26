import argparse
import socket
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import ssl
import re
import urllib.request
import urllib.parse

DEFAULT_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,3306,3389,5900,8080]

SOCKET_TIMEOUT = 3.0

def tcp_connect(host, port, timeout=SOCKET_TIMEOUT, use_ssl=False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if use_ssl:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))
        return sock
    except Exception as e:
        return None

def grab_banner(host, port, sock):
    try:
        if port in (80, 8080):
            req = b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode()
            sock.sendall(req)
            data = sock.recv(4096)
            return data.decode(errors='ignore').strip()
        elif port in (443,):
            try:
                req = b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode()
                sock.sendall(req)
                data = sock.recv(4096)
                return data.decode(errors='ignore').strip()
            except Exception:
                return ""
        else:
            try:
                sock.sendall(b"\r\n")
            except Exception:
                pass
            data = sock.recv(4096)
            return data.decode(errors='ignore').strip()
    except Exception as e:
        return ""

def identify_service_from_banner(banner):
    if not banner:
        return None
    banner_lower = banner.lower()
    m = re.search(r"server:\s*([^\r\n]+)", banner, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"^ssh-?([^\s,]+)", banner, re.IGNORECASE | re.MULTILINE)
    if m:
        return "SSH " + m.group(0).strip()
    m = re.search(r"^220\s+([^\r\n]+)", banner, re.IGNORECASE | re.MULTILINE)
    if m:
        return "FTP " + m.group(1).strip()
    if "mysql" in banner_lower or "mariadb" in banner_lower:
        return "MySQL/MariaDB " + banner.strip().splitlines()[0][:120]
    # Generic fallback: return first line
    return banner.strip().splitlines()[0][:200]

def cve_lookup(nvdcve_query):
    try:
        base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        query = urllib.parse.urlencode({"keywordSearch": nvdcve_query, "resultsPerPage": "5"})
        url = base + "?" + query
        with urllib.request.urlopen(url, timeout=6) as resp:
            data = resp.read().decode()
            parsed = json.loads(data)
            results = []
            for item in parsed.get("vulnerabilities", [])[:5]:
                vuln = item.get("cve", {})
                vuln_id = vuln.get("id")
                desc = ""
                descriptions = vuln.get("descriptions", [])
                if descriptions:
                    desc = descriptions[0].get("value", "")[:500]
                metrics = vuln.get("metrics", {})
                results.append({"id": vuln_id, "description": desc, "metrics": metrics})
            return {"ok": True, "query": nvdcve_query, "results": results}
    except Exception as e:
        return {"ok": False, "error": str(e), "query": nvdcve_query}

def scan_port(host, port):
    entry = {"port": port, "open": False, "banner": None, "service": None, "cve": None}
    use_ssl = port == 443
    sock = tcp_connect(host, port, use_ssl=use_ssl)
    if not sock:
        return entry
    entry["open"] = True
    try:
        banner = grab_banner(host, port, sock)
        entry["banner"] = banner
        entry["service"] = identify_service_from_banner(banner)
    except Exception as e:
        entry["banner"] = ""
    finally:
        try:
            sock.close()
        except Exception:
            pass
    if entry["service"]:
        query = entry["service"]
        cve_res = cve_lookup(query)
        entry["cve"] = cve_res
    return entry

def run_scan(target, ports, threads=20):
    report = {"target": target, "scanned_at": datetime.utcnow().isoformat()+"Z", "results": []}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, target, p): p for p in ports}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                res = fut.result()
                report["results"].append(res)
            except Exception as e:
                report["results"].append({"port": p, "error": str(e)})
    report["results"] = sorted(report["results"], key=lambda x: x.get("port", 0))
    return report

def parse_ports_arg(ports_arg):
    ports = set()
    for part in ports_arg.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a,b = part.split("-",1)
            a = int(a); b = int(b)
            for p in range(a, b+1):
                ports.add(p)
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(description="Lightweight Python vulnerability recon scanner")
    parser.add_argument("--target", "-t", required=True, help="Target hostname or IP")
    parser.add_argument("--ports", "-p", default="80,443,22", help="Comma-separated ports or ranges (e.g. 1-1024,80,443)")
    parser.add_argument("--threads", type=int, default=20, help="Number of worker threads")
    parser.add_argument("--output", "-o", default="scan_report.json", help="JSON output file")
    args = parser.parse_args()

    ports = parse_ports_arg(args.ports)
    print(f"[+] Scanning {args.target} ports: {ports} (threads={args.threads})")
    report = run_scan(args.target, ports, threads=args.threads)
    with open(args.output, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"[+] Scan complete. Report saved to {args.output}")

if __name__ == "__main__":
    main()
