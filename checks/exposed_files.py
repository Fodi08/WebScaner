# checks/exposed_files.py

def check_exposed_files(session, url):
    """Check for exposed sensitive files in website root"""
    
    # Files to check: [path, description, severity]
    sensitive_files = [
        ('/.env', 'Environment file with secrets (passwords, API keys)', 'Critical'),
        ('/backup.sql', 'Database backup file', 'Critical'),
        ('/database.sql', 'Database dump', 'Critical'),
        ('/.git/config', 'Git repository config (source code leak)', 'High'),
        ('/phpinfo.php', 'PHP info page (server configuration)', 'Medium'),
        ('/config.php', 'Application config file', 'High'),
        ('/wp-config.php', 'WordPress config (database credentials)', 'Critical'),
        ('/robots.txt', 'Robots file (site structure info)', 'Info'),
        ('/sitemap.xml', 'Site map', 'Info'),
    ]
    
    findings = []
    
    for path, description, severity in sensitive_files:
        target_url = url + path
        try:
            response = session.get(target_url, timeout=5, verify=False)
            
            # If file found (status 200) and not empty
            if response.status_code == 200 and len(response.content) > 0:
                findings.append({
                    'severity': severity,
                    'file': path,
                    'status': 'FOUND',
                    'info': description,
                    'url': target_url
                })
            elif response.status_code in [403, 401]:
                # File exists but access denied - still useful info
                findings.append({
                    'severity': 'Info',
                    'file': path,
                    'status': 'FORBIDDEN',
                    'info': f'File exists but access denied ({response.status_code})',
                    'url': target_url
                })
                
        except Exception:
            # File not found or network error - skip
            pass
            
    return findings