SQL Vulnerable lab (GUI)

A beginner-friendly Python GUI tool for detecting basic SQL Injection vulnerabilities, login bypass attempts, and performing a basic web crawler with scanner functionality. Built using `Tkinter, `Requests`, and `BeautifulSoup`.

Features
1. SQLi Scanner
- Test URLs with parameters for SQL Injection vulnerabilities.
- Uses common payloads like `' OR '1'='1`.
- Checks for error messages or HTTP 500 responses.

2. Login Bypass
- Attempts SQLi-based login bypass on custom login forms.
- Detects successful bypass via:
  - Keyword matches 
  - Content length difference
  - Redirect detection

3. Crawler + Scanner
- Crawls a given domain and extracts internal links.
- Scans crawled URLs with query parameters for SQL injection vulnerabilities.

