import requests
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# XSS scanner
def test_xss(url):
    payload = "<script>alert(1)</script>"
    try:
        response = requests.get(url + "?q=" + payload)
        if payload in response.text:
            return True
    except:
        pass
    return False

# SQL Injection scanner
def test_sql_injection(url):
    payload = "' OR '1'='1"
    try:
        response = requests.get(url + "?id=" + payload)
        if "mysql" in response.text.lower() or "syntax" in response.text.lower():
            return True
    except:
        pass
    return False

# Web crawler
def crawl(url):
    visited = set()
    to_visit = [url]
    while to_visit:
        current = to_visit.pop()
        if current in visited:
            continue
        visited.add(current)
        try:
            response = requests.get(current)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                absolute = requests.compat.urljoin(current, link['href'])
                if url in absolute and absolute not in visited:
                    to_visit.append(absolute)
        except:
            continue
    return visited

# Run scanners on URLs
def scan_site(urls):
    results = []
    for url in urls:
        print(f"Scanning: {url}")
        xss = test_xss(url)
        sql = test_sql_injection(url)
        results.append({
            "url": url,
            "xss_vulnerable": xss,
            "sql_injection_vulnerable": sql
        })
    return results

# PDF report generator
def generate_report(results, filename="scan_report.pdf"):
    c = canvas.Canvas(filename, pagesize=A4)
    c.drawString(100, 800, "Web Application Vulnerability Scan Report")
    y = 750
    for result in results:
        c.drawString(100, y, f"URL: {result['url']}")
        y -= 20
        c.drawString(120, y, f"XSS Vulnerable: {'Yes' if result['xss_vulnerable'] else 'No'}")
        y -= 20
        c.drawString(120, y, f"SQL Injection Vulnerable: {'Yes' if result['sql_injection_vulnerable'] else 'No'}")
        y -= 40
        if y < 100:
            c.showPage()
            y = 800
    c.save()

# Main entry point
if __name__ == "__main__":
    target_url = "http://testphp.vulnweb.com"  # Replace with your target
    urls = crawl(target_url)
    results = scan_site(urls)
    generate_report(results)
    print("Scan complete. Report saved as 'scan_report.pdf'")

