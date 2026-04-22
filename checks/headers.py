# checks/headers.py

def check_security_headers(session, url):
    """Проверяет наличие важных security-заголовков"""
    findings = []
    
    required_headers = {
        'Strict-Transport-Security': 'HSTS не включен (риск перехвата трафика)',
        'X-Frame-Options': 'Защита от Clickjacking отсутствует',
        'X-Content-Type-Options': 'Защита от MIME-sniffing отсутствует',
        'Content-Security-Policy': 'CSP не настроен (риск XSS)'
    }

    try:
        response = session.get(url, timeout=10, verify=False)
        headers = response.headers

        for header, issue in required_headers.items():
            if header not in headers:
                findings.append({
                    'severity': 'Medium',
                    'header': header,
                    'status': 'MISSING',
                    'info': issue
                })
            else:
                findings.append({
                    'severity': 'Info',
                    'header': header,
                    'status': 'OK',
                    'info': 'Header is present'
                })
        return findings

    except Exception as e:
        return [{'severity': 'Critical', 'header': 'Connection', 'status': 'ERROR', 'info': str(e)}]