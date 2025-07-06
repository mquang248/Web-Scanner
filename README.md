# Web Security Scanner

A powerful and modern web application security scanner that helps identify common security vulnerabilities and misconfigurations in web applications.

## Features

### Security Checks
- Security Headers Analysis
  - HSTS
  - X-Frame-Options
  - Content Security Policy (CSP)
  - X-Content-Type-Options
  - X-XSS-Protection
  - Referrer-Policy
  - Permissions-Policy

- SSL/TLS Security
  - Certificate validation
  - Protocol versions
  - Cipher suites

- Common Vulnerabilities
  - Cross-Site Scripting (XSS)
  - SQL Injection
  - Open Redirect
  - Information Disclosure
  - File Inclusion
  - Mixed Content
  - CSRF Protection

### Additional Features
- Recursive crawling with configurable depth
- Multi-threaded scanning
- Beautiful terminal UI with progress bars
- Detailed HTML reports
- Remediation recommendations

## Installation

### Linux
```bash
# Clone the repository
git clone https://github.com/248/web-scanner.git
cd web-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Windows
```powershell
# Clone the repository
git clone https://github.com/248/web-scanner.git
cd web-scanner

# Create virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

Basic scan:
```bash
./scanner.py --url https://example.com
```

Advanced options:
```bash
./scanner.py --url https://example.com --depth 3 --threads 10 --verbose --html
```

Parameters:
- `--url`: Target URL to scan
- `--depth`: Crawling depth (default: 2)
- `--threads`: Number of concurrent threads (default: 5)
- `--verbose`: Enable detailed output
- `--html`: Generate HTML report

## Output
- Terminal output with color-coded findings
- HTML report in `reports/` directory (when using --html)
- Findings categorized by severity (High, Medium, Low)
- Detailed remediation recommendations

## Security Note
⚠️ This tool should only be used for security testing of systems you own or have explicit permission to test. Unauthorized scanning may be illegal.

## License
MIT License

Copyright (c) 2025 Manh Quang

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 