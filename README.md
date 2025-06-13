# Universal-injector
# ⚔️ Universal Injector

**A fast and lightweight web injection scanner for bug bounty and ethical hacking.**

---

## 🚀 Features

- GET/POST injection scanning
- XSS, SQLi, LFI, Command Injection detection
- Timing-based blind injection detection
- Custom headers support (JWT, API keys, etc.)
- Threaded for high performance
- Logs findings to `vuln_results.txt`

---

## 🛠️ Usage

```bash
python3 universal_injector.py
You’ll be prompted to enter:

Target URL with GET params

Payload wordlist (e.g., injection.txt)

HTTP method (GET/POST)

Custom headers in JSON

Verbose mode (optional)

📥 Sample Input
pgsql

[?] Enter target URL with GET params: https://site.com/search?q=test
[?] Wordlist path: injection.txt
[?] Method: GET
[?] Headers (JSON): {"Authorization": "Bearer eyJ..."}
[?] Verbose mode? y/N: y
📄 Output
Results saved in vuln_results.txt:

q => ' OR 1=1 -- [SQLi]
URL: https://site.com/search?q=%27+OR+1%3D1+--

q => <script>alert(1)</script> [XSS]
URL: https://site.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
📦 Requirements
nginx
requests
colorama
Install with:
pip install -r requirements.txt
👨‍💻 Author
Naveed Qadir
Bug Bounty Hunter & Cyber Security Student
🔗 GitHub

🛡️ Legal Disclaimer
This tool is for educational and authorized testing only. Do not use it on systems without permission

---

### 📄 3. **`requirements.txt`**

```txt
requests
colorama
📜 4. License (MIT Recommended)
Create a LICENSE file with this (MIT License):

MIT License

Copyright (c) 2025 Naveed Qadir

Permission is hereby granted, free of charge, to any person obtaining a copy
...

name of tool
universal_injector

