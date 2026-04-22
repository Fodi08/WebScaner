# checks/tech_stack.py
import re
from bs4 import BeautifulSoup

def check_tech_stack(session, url):
    """Определяет технологии: веб-сервер, язык программирования, CMS"""
    findings = []
    
    try:
        response = session.get(url, timeout=10, verify=False)
        headers = response.headers
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. Определение веб-сервера по заголовку Server
        server_header = headers.get('Server', '')
        if server_header:
            findings.append({
                'category': 'Technology',
                'severity': 'Info',
                'item': 'Web Server',
                'status': 'DETECTED',
                'info': f'Обнаружен сервер: {server_header}'
            })
        else:
            findings.append({
                'category': 'Technology',
                'severity': 'Info',
                'item': 'Web Server',
                'status': 'HIDDEN',
                'info': 'Заголовок Server скрыт (рекомендуемая практика)'
            })
            
        # 2. Определение языка/фреймворка по X-Powered-By
        x_powered = headers.get('X-Powered-By', '')
        if x_powered:
            findings.append({
                'category': 'Technology',
                'severity': 'Low',
                'item': 'Language/Stack',
                'status': 'DETECTED',
                'info': f'Обнаружен стек: {x_powered} (раскрытие информации)'
            })
            
        # 3. Определение CMS через meta-тег generator
        meta_gen = soup.find('meta', attrs={'name': 'generator'})
        if meta_gen:
            cms_name = meta_gen.get('content', '')
            findings.append({
                'category': 'Technology',
                'severity': 'Info',
                'item': 'CMS',
                'status': 'DETECTED',
                'info': f'Обнаружена CMS: {cms_name}'
            })
            
        # 4. Фоллбэк: проверка по характерным путям (HEAD-запрос быстрее)
        cms_paths = {
            '/wp-content/': 'WordPress',
            '/sites/default/': 'Drupal',
            '/media/jui/': 'Joomla',
            '/bitrix/': '1C-Bitrix',
            '/assets/': 'Static Assets Framework'
        }
        
        for path, cms in cms_paths.items():
            try:
                resp = session.head(url + path, timeout=3, allow_redirects=True)
                if resp.status_code == 200:
                    findings.append({
                        'category': 'Technology',
                        'severity': 'Info',
                        'item': 'CMS',
                        'status': 'DETECTED',
                        'info': f'Обнаружена CMS по структуре: {cms}'
                    })
                    break
            except Exception:
                continue
                
    except Exception as e:
        findings.append({
            'category': 'Technology',
            'severity': 'Error',
            'item': 'Detection',
            'status': 'FAILED',
            'info': str(e)
        })
        
    return findings