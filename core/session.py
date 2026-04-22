# core/session.py
import requests
import urllib3

# Отключаем предупреждения о небезопасных SSL-сертификатах
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_session():
    """Создает настроенную HTTP-сессию для сканера"""
    session = requests.Session()
    
    # Притворяемся обычным браузером
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    })
    
    return session