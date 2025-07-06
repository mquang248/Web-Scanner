#!/usr/bin/env python3

import argparse
import logging
import sys
from typing import List, Dict, Optional
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import validators
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor
import threading
from tqdm import tqdm
import re
from datetime import datetime
import time
from jinja2 import Template
import pdfkit
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import socket
import os
import json
import aiohttp
import asyncio
import nmap

# Initialize colorama for cross-platform colored output
init()

class Scanner:
    def __init__(self, url: str, depth: int = 2, threads: int = 5, verbose: bool = False, html: bool = False):
        self.base_url = url
        self.depth = depth
        self.threads = threads
        self.verbose = verbose
        self.html = html
        self.visited_urls = set()
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.technologies = set()
        
        # Configure logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Configure session with common headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

        # Remediation tips
        self.remediation_tips = {
            'security_header': {
                'HSTS': "Add the Strict-Transport-Security header with appropriate max-age",
                'X-Frame-Options': "Add the X-Frame-Options header to prevent clickjacking",
                'X-Content-Type-Options': "Add the X-Content-Type-Options header to prevent MIME-type sniffing",
                'X-XSS-Protection': "Add the X-XSS-Protection header for basic XSS protection",
                'Referrer-Policy': "Add the Referrer-Policy header to control referrer information",
                'Permissions-Policy': "Add the Permissions-Policy header to control browser features"
            },
            'csp': "Implement a strong Content Security Policy with specific sources and avoid unsafe directives",
            'mixed_content': "Update all resource URLs to use HTTPS and implement HSTS",
            'xss': "Implement proper input validation and output encoding",
            'sql_injection': "Use parameterized queries and input validation",
            'open_redirect': "Implement proper URL validation and whitelist of allowed redirect destinations",
            'info_disclosure': "Remove or protect sensitive files from public access",
            'misconfiguration': "Restrict access to sensitive interfaces and remove unnecessary services",
            'ssl_tls': "Upgrade to TLS 1.2/1.3 and use strong cipher suites"
        }

    def print_banner(self):
        """Print a cool banner."""
        banner = f"""
{Fore.CYAN}
 ██╗    ██╗███████╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
 ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██║ █╗ ██║█████╗  ██████╔╝    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ╚███╔███╔╝███████╗██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{Style.RESET_ALL}

                    {Fore.YELLOW}[ Advanced Web Application Security Scanner - Version 1.0.0 ]{Style.RESET_ALL}
                            {Fore.YELLOW}[ Developed by Manh Quang - https://github.com/248 ]{Style.RESET_ALL}
"""
        print(banner)
        print(f"{Fore.GREEN}Target: {self.base_url}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

    def detect_technologies(self, response: requests.Response):
        """Detect technologies used by the website."""
        headers = response.headers
        html = response.text
        
        # Check headers
        if 'X-Powered-By' in headers:
            self.technologies.add(f"Powered by: {headers['X-Powered-By']}")
        if 'Server' in headers:
            self.technologies.add(f"Server: {headers['Server']}")
        
        # Check common frameworks and libraries
        tech_patterns = {
            'jQuery': r'jquery.*\.js',
            'React': r'react.*\.js|<div.*data-reactroot',
            'Vue.js': r'vue.*\.js|<div.*v-',
            'Angular': r'angular.*\.js|ng-app',
            'Bootstrap': r'bootstrap.*\.css',
            'WordPress': r'wp-content|wp-includes',
            'Laravel': r'laravel.*\.js|csrf-token',
            'Django': r'csrfmiddlewaretoken|django',
            'Flask': r'flask.*\.js|flask-session',
            'ASP.NET': r'__VIEWSTATE|asp.net',
            'PHP': r'\.php$|PHPSESSID',
            'Node.js': r'node_modules|express'
        }
        
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, html, re.I):
                self.technologies.add(tech)

    def print_progress(self, message: str):
        """Print progress message with spinner."""
        print(f"{Fore.CYAN}[*] {message}...{Style.RESET_ALL}")

    def print_vulnerability(self, vuln: Dict):
        """Print vulnerability details to terminal."""
        severity_colors = {
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.BLUE
        }
        color = severity_colors.get(vuln['severity'], Fore.WHITE)
        
        print(f"\n{color}{'='*80}{Style.RESET_ALL}")
        print(f"{color}[{vuln['severity']} Risk] {vuln['type']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Description: {vuln['description']}{Style.RESET_ALL}")
        
        if vuln.get('evidence'):
            print(f"{Fore.WHITE}Evidence: {vuln['evidence']}{Style.RESET_ALL}")
        
        if vuln.get('remediation'):
            print(f"\n{Fore.GREEN}Remediation:{Style.RESET_ALL}")
            print(f"{vuln['remediation']}")
        
        print(f"{color}{'='*80}{Style.RESET_ALL}\n")

    def generate_report(self):
        """Generate a security report."""
        self.print_banner()
        
        # Print technologies detected
        if self.technologies:
            print(f"\n{Fore.CYAN}[*] Technologies Detected:{Style.RESET_ALL}")
            for tech in sorted(self.technologies):
                print(f"    {Fore.GREEN}▸{Style.RESET_ALL} {tech}")
        
        # Group vulnerabilities by severity
        vuln_by_severity = {'High': [], 'Medium': [], 'Low': []}
        for vuln in self.vulnerabilities:
            vuln_by_severity[vuln['severity']].append(vuln)
        
        # Print summary
        print(f"\n{Fore.CYAN}[*] Scan Summary:{Style.RESET_ALL}")
        print(f"    {Fore.GREEN}▸{Style.RESET_ALL} Total URLs scanned: {len(self.visited_urls)}")
        print(f"    {Fore.GREEN}▸{Style.RESET_ALL} Total vulnerabilities found: {len(self.vulnerabilities)}")
        print(f"    {Fore.GREEN}▸{Style.RESET_ALL} Scan duration: {time.strftime('%H:%M:%S', time.gmtime(time.time() - self.start_time))}")
        
        # Print vulnerabilities by severity
        for severity in ['High', 'Medium', 'Low']:
            vulns = vuln_by_severity[severity]
            if vulns:
                print(f"\n{Fore.CYAN}[*] {severity} Severity Vulnerabilities ({len(vulns)}):{Style.RESET_ALL}")
                for vuln in vulns:
                    self.print_vulnerability(vuln)

        # Generate HTML report if requested
        if self.html:
            self.generate_html_report(vuln_by_severity)

    def generate_html_report(self, vuln_by_severity: Dict):
        """Generate an HTML report."""
        with open('templates/report_template.html', 'r') as f:
            template = Template(f.read())

        scan_duration = time.strftime('%H:%M:%S', time.gmtime(time.time() - self.start_time))
        
        html_content = template.render(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            target_url=self.base_url,
            total_urls=len(self.visited_urls),
            total_vulnerabilities=len(self.vulnerabilities),
            scan_duration=scan_duration,
            vulnerabilities=vuln_by_severity,
            technologies=sorted(self.technologies)
        )

        # Create reports directory if it doesn't exist
        os.makedirs('reports', exist_ok=True)

        # Save HTML report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = urlparse(self.base_url).netloc.replace(':', '_')
        html_file = f"reports/security_scan_{domain}_{timestamp}.html"
        
        with open(html_file, 'w') as f:
            f.write(html_content)
        self.logger.info(f"HTML report saved to: {html_file}")

    def validate_url(self) -> bool:
        """Validate the target URL."""
        if not validators.url(self.base_url):
            self.logger.error(f"Invalid URL: {self.base_url}")
            return False
        return True

    def scan(self):
        """Main scanning method."""
        if not self.validate_url():
            return

        self.print_banner()
        
        try:
            # Configure progress bar format
            bar_format = "{desc:<30} |{bar:50}| {percentage:3.0f}%"
            
            print(f"\n{Fore.CYAN}[*] Starting security scan...{Style.RESET_ALL}\n")
            
            # Initial response
            with tqdm(total=100, desc="Target accessibility", bar_format=bar_format, colour='green') as pbar:
                response = self.session.get(self.base_url)
                self.detect_technologies(response)
                for i in range(0, 101, 20):
                    time.sleep(0.1)
                    pbar.update(20)
            
            print(f"\n{Fore.CYAN}[*] Basic security checks...{Style.RESET_ALL}\n")
            
            # Basic checks
            with tqdm(total=100, desc="Security headers", bar_format=bar_format, colour='green') as pbar:
                self.check_security_headers()
                for i in range(0, 101, 20):
                    time.sleep(0.1)
                    pbar.update(20)
            
            with tqdm(total=100, desc="Mixed content", bar_format=bar_format, colour='green') as pbar:
                self.check_mixed_content()
                for i in range(0, 101, 20):
                    time.sleep(0.1)
                    pbar.update(20)
            
            with tqdm(total=100, desc="CSP configuration", bar_format=bar_format, colour='green') as pbar:
                self.check_csp()
                for i in range(0, 101, 20):
                    time.sleep(0.1)
                    pbar.update(20)
            
            with tqdm(total=100, desc="SSL/TLS security", bar_format=bar_format, colour='green') as pbar:
                self.check_ssl_tls()
                for i in range(0, 101, 20):
                    time.sleep(0.1)
                    pbar.update(20)

            print(f"\n{Fore.YELLOW}[*] Advanced security checks...{Style.RESET_ALL}\n")

            # Advanced checks
            with tqdm(total=100, desc="Information disclosure", bar_format=bar_format, colour='yellow') as pbar:
                total_files = len(self.get_sensitive_files())
                for i, _ in enumerate(self.check_info_disclosure(), 1):
                    pbar.update(int(100 * i / total_files))
                    time.sleep(0.1)
            
            with tqdm(total=100, desc="Security misconfigurations", bar_format=bar_format, colour='yellow') as pbar:
                total_checks = len(self.get_misconfig_checks())
                for i, _ in enumerate(self.check_misconfigurations(), 1):
                    pbar.update(int(100 * i / total_checks))
                    time.sleep(0.1)
            
            print(f"\n{Fore.RED}[*] Deep vulnerability scanning...{Style.RESET_ALL}\n")
            
            # Start crawling and vulnerability scanning
            with tqdm(total=100, desc="Deep scan progress", bar_format=bar_format, colour='red') as pbar:
                self.crawl_and_scan(pbar)
            
            # Generate report
            print(f"\n{Fore.GREEN}[✓] Scan completed successfully!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Generating final report...{Style.RESET_ALL}\n")
            self.generate_report()
            
        except Exception as e:
            print(f"\n{Fore.RED}[✗] Error: {str(e)}{Style.RESET_ALL}")
            self.logger.error(f"An error occurred during scanning: {str(e)}")
            raise

    def get_sensitive_files(self):
        """Get list of sensitive files to check."""
        return [
            'robots.txt',
            '.git/config',
            '.env',
            'phpinfo.php',
            'server-status',
            '.htaccess',
            'web.config',
            'crossdomain.xml',
            'composer.json',
            'package.json',
            'webpack.config.js',
            'config.yml',
            'backup.zip',
            'backup.sql',
            'dump.sql'
        ]

    def get_misconfig_checks(self):
        """Get list of misconfiguration checks."""
        return [
            {
                'path': 'phpmyadmin/',
                'pattern': 'phpMyAdmin',
                'type': 'Database Management Interface'
            },
            {
                'path': 'admin/',
                'pattern': 'login|admin|dashboard',
                'type': 'Admin Interface'
            },
            {
                'path': 'wp-admin/',
                'pattern': 'WordPress',
                'type': 'WordPress Admin'
            },
            {
                'path': 'console/',
                'pattern': 'console|terminal|shell',
                'type': 'Web Console'
            },
            {
                'path': '.svn/entries',
                'pattern': 'svn|revision|repository',
                'type': 'SVN Repository'
            }
        ]

    def check_info_disclosure(self):
        """Check for information disclosure vulnerabilities."""
        common_files = self.get_sensitive_files()
        
        base_url = self.base_url.rstrip('/')
        for file in common_files:
            try:
                url = f"{base_url}/{file}"
                response = self.session.get(url)
                if response.status_code == 200:
                    # Check content for sensitive information
                    sensitive_patterns = [
                        r'password|passwd|pwd',
                        r'api[_-]?key',
                        r'secret[_-]?key',
                        r'database|db_|mysql',
                        r'config|configuration',
                        r'admin|root',
                        r'private|confidential'
                    ]
                    
                    content = response.text.lower()
                    for pattern in sensitive_patterns:
                        if re.search(pattern, content):
                            self.add_vulnerability(
                                'info_disclosure',
                                f'Potential information disclosure in {file}',
                                'High',
                                evidence=f"Found sensitive information pattern in {url}",
                                remediation=self.remediation_tips['info_disclosure']
                            )
                            break
            except:
                pass
            yield

    def check_misconfigurations(self):
        """Check for common security misconfigurations."""
        checks = self.get_misconfig_checks()
        
        base_url = self.base_url.rstrip('/')
        for check in checks:
            try:
                url = f"{base_url}/{check['path']}"
                response = self.session.get(url)
                if response.status_code != 404:
                    if re.search(check['pattern'], response.text, re.I):
                        self.add_vulnerability(
                            'misconfiguration',
                            f'Exposed {check["type"]} detected',
                            'High',
                            evidence=f"Found at: {url}",
                            remediation=self.remediation_tips['misconfiguration']
                        )
            except:
                pass
            yield

    def crawl_and_scan(self, pbar=None):
        """Crawl the website and scan for vulnerabilities."""
        self.logger.info("Starting crawl and vulnerability scan...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future = executor.submit(self.crawl, self.base_url, 0)
            progress = 0
            while not future.done():
                if pbar and progress < 95:
                    pbar.update(5)
                    progress += 5
                time.sleep(0.5)
            if pbar:
                pbar.update(100 - progress)

    def crawl(self, url: str, current_depth: int):
        """Crawl the website and collect links."""
        if current_depth >= self.depth or url in self.visited_urls:
            return

        with self.lock:
            self.visited_urls.add(url)

        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Test for vulnerabilities
            self.test_xss(url, response)
            self.test_sql_injection(url)
            self.test_open_redirect(url)
            
            # Extract and follow links
            if current_depth < self.depth:
                links = soup.find_all('a')
                for link in links:
                    href = link.get('href')
                    if href:
                        absolute_url = urljoin(url, href)
                        if (absolute_url.startswith(self.base_url) and 
                            absolute_url not in self.visited_urls):
                            self.crawl(absolute_url, current_depth + 1)
                            
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {str(e)}")

    def add_vulnerability(self, type: str, description: str, severity: str, evidence: str = None, remediation: str = None):
        """Add a vulnerability to the list."""
        with self.lock:
            self.vulnerabilities.append({
                'type': type,
                'description': description,
                'severity': severity,
                'evidence': evidence,
                'remediation': remediation or self.remediation_tips.get(type, '')
            })
            if self.verbose:
                self.logger.debug(f"{Fore.RED}Found {severity} vulnerability: {description}{Fore.RESET}")

    def check_security_headers(self):
        """Check for security headers."""
        self.logger.info("Checking security headers...")
        response = self.session.get(self.base_url)
        headers = response.headers
        
        security_headers = {
            'Strict-Transport-Security': {
                'message': 'Missing HSTS header',
                'key': 'HSTS'
            },
            'X-Frame-Options': {
                'message': 'Missing X-Frame-Options header',
                'key': 'X-Frame-Options'
            },
            'X-Content-Type-Options': {
                'message': 'Missing X-Content-Type-Options header',
                'key': 'X-Content-Type-Options'
            },
            'X-XSS-Protection': {
                'message': 'Missing X-XSS-Protection header',
                'key': 'X-XSS-Protection'
            },
            'Referrer-Policy': {
                'message': 'Missing Referrer-Policy header',
                'key': 'Referrer-Policy'
            },
            'Permissions-Policy': {
                'message': 'Missing Permissions-Policy header',
                'key': 'Permissions-Policy'
            }
        }
        
        for header, info in security_headers.items():
            if header not in headers:
                self.add_vulnerability(
                    'security_header',
                    info['message'],
                    'Medium',
                    remediation=self.remediation_tips['security_header'][info['key']]
                )

    def check_mixed_content(self):
        """Check for mixed content issues."""
        self.logger.info("Checking for mixed content...")
        response = self.session.get(self.base_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        resources = {
            'script': 'src',
            'link': 'href',
            'img': 'src',
            'iframe': 'src'
        }
        
        for tag, attr in resources.items():
            for element in soup.find_all(tag):
                resource_url = element.get(attr)
                if resource_url and resource_url.startswith('http://'):
                    self.add_vulnerability(
                        'mixed_content',
                        f'Mixed content found: {resource_url}',
                        'High',
                        evidence=str(element),
                        remediation=self.remediation_tips['mixed_content']
                    )

    def check_csp(self):
        """Check Content Security Policy."""
        self.logger.info("Checking Content Security Policy...")
        response = self.session.get(self.base_url)
        headers = response.headers
        
        csp_headers = [
            'Content-Security-Policy',
            'Content-Security-Policy-Report-Only'
        ]
        
        csp_found = False
        for header in csp_headers:
            if header in headers:
                csp_found = True
                self.analyze_csp(headers[header])
                
        if not csp_found:
            self.add_vulnerability(
                'csp',
                'No Content Security Policy found',
                'High',
                remediation=self.remediation_tips['csp']
            )

    def analyze_csp(self, csp: str):
        """Analyze Content Security Policy for common misconfigurations."""
        directives = csp.split(';')
        for directive in directives:
            directive = directive.strip()
            if "unsafe-inline" in directive or "unsafe-eval" in directive:
                self.add_vulnerability(
                    'csp',
                    f'Unsafe CSP directive found: {directive}',
                    'Medium',
                    evidence=directive,
                    remediation=self.remediation_tips['csp']
                )
            if "*" in directive:
                self.add_vulnerability(
                    'csp',
                    f'Overly permissive CSP directive found: {directive}',
                    'Medium',
                    evidence=directive,
                    remediation=self.remediation_tips['csp']
                )

    def check_ssl_tls(self):
        """Check SSL/TLS configuration."""
        self.logger.info("Checking SSL/TLS configuration...")
        parsed_url = urlparse(self.base_url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443

        try:
            # Basic SSL/TLS check
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                    
                    # Check certificate expiration
                    if x509_cert.not_valid_after < datetime.now():
                        self.add_vulnerability(
                            'ssl_tls',
                            'SSL certificate has expired',
                            'High',
                            remediation=self.remediation_tips['ssl_tls']
                        )
                    
                    # Check protocol version
                    version = ssock.version()
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.add_vulnerability(
                            'ssl_tls',
                            f'Weak SSL/TLS version in use: {version}',
                            'High',
                            remediation=self.remediation_tips['ssl_tls']
                        )

                    # Check cipher suite
                    cipher = ssock.cipher()
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
                    if any(weak in cipher[0] for weak in weak_ciphers):
                        self.add_vulnerability(
                            'ssl_tls',
                            f'Weak cipher suite in use: {cipher[0]}',
                            'High',
                            remediation=self.remediation_tips['ssl_tls']
                        )

        except ssl.SSLError as e:
            self.add_vulnerability(
                'ssl_tls',
                f'SSL/TLS Error: {str(e)}',
                'High',
                remediation=self.remediation_tips['ssl_tls']
            )
        except Exception as e:
            self.logger.error(f"Error checking SSL/TLS: {str(e)}")

    def test_sql_injection(self, url: str, params: Dict = None):
        """Test for SQL injection vulnerabilities."""
        # Time-based payloads
        time_payloads = [
            "' WAITFOR DELAY '0:0:5'--",
            "1) WAITFOR DELAY '0:0:5'--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            ") OR (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ]
        
        # Error-based payloads
        error_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 'x'='x",
            "') OR ('x'='x",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT @@version--"
        ]
        
        # Boolean-based payloads
        boolean_payloads = [
            "' AND '1'='1",
            "' AND '1'='2",
            "' OR '1'='1' AND '1'='2",
            "1 AND 1=1",
            "1 AND 1=2",
            "1) AND (1=1",
            "1) AND (1=2"
        ]
        
        def test_payload(test_url: str, original_response: requests.Response):
            try:
                start_time = time.time()
                test_response = self.session.get(test_url, timeout=10)
                response_time = time.time() - start_time
                
                # Check for SQL errors
                error_patterns = [
                    'sql syntax',
                    'mysql error',
                    'sql server error',
                    'oracle error',
                    'postgresql error',
                    'sqlite error',
                    'database error',
                    'odbc driver error',
                    'sql command not properly ended'
                ]
                
                if any(pattern in test_response.text.lower() for pattern in error_patterns):
                    return True, 'error', test_response.text
                
                # Check for time-based
                if response_time > 5:
                    return True, 'time', f"Response time: {response_time:.2f}s"
                
                # Check for boolean-based
                if len(test_response.text) != len(original_response.text):
                    return True, 'boolean', f"Response length difference: {len(test_response.text) - len(original_response.text)}"
                
            except requests.Timeout:
                return True, 'time', "Request timed out"
            except:
                pass
            return False, None, None
        
        # Test URL parameters
        parsed = urlparse(url)
        if parsed.query:
            original_response = self.session.get(url)
            params = parse_qs(parsed.query)
            
            for param_name, param_values in params.items():
                # Test all types of payloads
                for payload_type, payloads in [
                    ('time', time_payloads),
                    ('error', error_payloads),
                    ('boolean', boolean_payloads)
                ]:
                    for payload in payloads:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_url = url.split('?')[0] + '?' + '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
                        
                        is_vuln, vuln_type, evidence = test_payload(test_url, original_response)
                        if is_vuln:
                            self.add_vulnerability(
                                'sql_injection',
                                f'Potential {vuln_type}-based SQL injection vulnerability in parameter: {param_name}',
                                'High',
                                evidence=f"URL: {test_url}\nType: {vuln_type}\nEvidence: {evidence}",
                                remediation="Use parameterized queries and input validation"
                            )
                            return  # Stop testing this parameter after finding a vulnerability

    def test_xss(self, url: str, response: requests.Response):
        """Test for XSS vulnerabilities."""
        # Basic XSS payloads
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '"><svg/onload=alert(1)>',
            "javascript:alert(1)",
            "';alert(1);//",
            '"><iframe src="javascript:alert(1)">',
            '"><input onfocus=alert(1) autofocus>',
            '"><select onmouseover=alert(1)>',
            '"><marquee onstart=alert(1)>'
        ]
        
        # Test URL parameters
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name, param_values in params.items():
                for payload in payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = url.split('?')[0] + '?' + '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
                    try:
                        test_response = self.session.get(test_url)
                        if payload in test_response.text:
                            self.add_vulnerability(
                                'xss',
                                f'Potential XSS vulnerability in parameter: {param_name}',
                                'High',
                                evidence=f"URL: {test_url}\nPayload reflected in response",
                                remediation="Implement proper input validation and output encoding"
                            )
                            break
                    except:
                        continue
        
        # Test form inputs
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all(['input', 'textarea'])
            for input_field in inputs:
                if input_field.get('type') not in ['hidden', 'submit', 'button', 'checkbox', 'radio']:
                    self.add_vulnerability(
                        'xss',
                        f'Potential XSS vulnerability in form input: {input_field.get("name")}',
                        'Medium',
                        evidence=str(input_field),
                        remediation="Implement input validation and output encoding for form fields"
                    )

    def test_open_redirect(self, url: str):
        """Test for open redirect vulnerabilities."""
        redirect_params = ['redirect', 'url', 'next', 'return', 'return_to', 'goto', 'to', 'link', 'link_to', 'location', 'forward']
        parsed = urlparse(url)
        
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name, param_values in params.items():
                if any(redirect in param_name.lower() for redirect in redirect_params):
                    test_urls = [
                        'https://evil.com',
                        '//evil.com',
                        'javascript:alert(1)',
                        'data:text/html,<script>alert(1)</script>',
                        '\\\\evil.com',
                        'https:evil.com',
                        '//google.com%2F@evil.com',
                        'https://evil.com/fake-login'
                    ]
                    
                    for test_url in test_urls:
                        test_params = params.copy()
                        test_params[param_name] = [test_url]
                        full_test_url = url.split('?')[0] + '?' + '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
                        try:
                            response = self.session.get(full_test_url, allow_redirects=False)
                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')
                                if any(evil in location.lower() for evil in ['evil.com', 'javascript:', 'data:', '\\\\']):
                                    self.add_vulnerability(
                                        'open_redirect',
                                        f'Open redirect vulnerability found in parameter: {param_name}',
                                        'High',
                                        evidence=f"URL: {full_test_url}\nRedirects to: {location}",
                                        remediation="Implement proper URL validation and whitelist of allowed redirect destinations"
                                    )
                                    break
                        except:
                            continue

def main():
    parser = argparse.ArgumentParser(description='Web Security Scanner')
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--depth', type=int, default=2, help='Crawling depth')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--html', action='store_true', help='Generate HTML report')
    args = parser.parse_args()

    try:
        scanner = Scanner(args.url, args.depth, args.threads, args.verbose, args.html)
        scanner.scan()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 