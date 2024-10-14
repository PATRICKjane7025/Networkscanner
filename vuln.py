vulners = {
    "FTP": {
        "Version 1.0": ["Vuln1: Anonymous Login", "Vuln2: Cleartext Transmission"],
        "Version 2.3": ["Vuln1: Directory Traversal", "Vuln2: DoS Attack"]
    },
    "SSH": {
        "OpenSSH 7.2": ["Vuln1: Weak Ciphers", "Vuln2: Default Credentials"],
        "OpenSSH 8.0": ["Vuln1: User Enumeration", "Vuln2: CVE-2019-6111"]
    },
    "Telnet": {
        "Version 1.0": ["Vuln1: Cleartext Communication", "Vuln2: Default Passwords"],
        "Version 2.5": ["Vuln1: Buffer Overflow", "Vuln2: DoS Vulnerability"]
    },
    "SMTP": {
        "Postfix 3.0": ["Vuln1: Open Relay", "Vuln2: Spoofing"],
        "Exim 4.92": ["Vuln1: RCE - CVE-2019-15846", "Vuln2: Spoofing"]
    },
    "DNS": {
        "BIND 9.10": ["Vuln1: Cache Poisoning", "Vuln2: Zone Transfer"],
        "BIND 9.11": ["Vuln1: DoS Vulnerability", "Vuln2: CVE-2018-5740"]
    },
    "HTTP": {
        "Apache 2.4.41": ["Vuln1: Directory Traversal", "Vuln2: XSS"],
        "Nginx 1.18": ["Vuln1: HTTP Request Smuggling", "Vuln2: DoS Vulnerability"]
    },
    "POP3": {
        "Dovecot 2.3": ["Vuln1: Cleartext Transmission", "Vuln2: Buffer Overflow"],
        "Courier 1.0": ["Vuln1: User Enumeration", "Vuln2: Weak Authentication"]
    },
    "IMAP": {
        "Dovecot 2.3": ["Vuln1: Cleartext Communication", "Vuln2: RCE Vulnerability"],
        "Courier 1.0": ["Vuln1: Buffer Overflow", "Vuln2: Information Disclosure"]
    },
    "SNMP": {
        "Net-SNMP 5.8": ["Vuln1: Weak Community String", "Vuln2: DoS Attack"],
        "Net-SNMP 5.7": ["Vuln1: Buffer Overflow", "Vuln2: Unauthorized Access"]
    },
    "HTTPS": {
        "Apache 2.4.46": ["Vuln1: SSLv3 Weakness", "Vuln2: Heartbleed - CVE-2014-0160"],
        "Nginx 1.17": ["Vuln1: Weak Cipher Suites", "Vuln2: HTTP/2 DoS"]
    },
    "MySQL": {
        "MySQL 5.7": ["Vuln1: SQL Injection", "Vuln2: Weak Authentication"],
        "MySQL 8.0": ["Vuln1: CVE-2020-14825", "Vuln2: Information Disclosure"]
    },
    "RDP - Remote Desktop": {
        "RDP 5.2": ["Vuln1: BlueKeep - CVE-2019-0708", "Vuln2: Weak Passwords"],
        "RDP 6.0": ["Vuln1: MITM Attack", "Vuln2: CVE-2012-0002"]
    },
    "PostgreSQL": {
        "PostgreSQL 9.6": ["Vuln1: SQL Injection", "Vuln2: Information Disclosure"],
        "PostgreSQL 12.3": ["Vuln1: Buffer Overflow", "Vuln2: CVE-2020-1720"]
    },
    "VNC": {
        "RealVNC 4.1": ["Vuln1: Weak Authentication", "Vuln2: Cleartext Transmission"],
        "TightVNC 1.3": ["Vuln1: Buffer Overflow", "Vuln2: Information Disclosure"]
    },
    "HTTP Proxy": {
        "Squid 3.5": ["Vuln1: HTTP Smuggling", "Vuln2: CVE-2020-15810"],
        "HAProxy 2.0": ["Vuln1: Buffer Overflow", "Vuln2: Weak Authentication"]
    }
}
