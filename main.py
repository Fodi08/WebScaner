# main.py
import sys
from colorama import init, Fore, Style
from core.session import create_session
from checks.headers import check_security_headers
from checks.exposed_files import check_exposed_files
from checks.tech_stack import check_tech_stack
from core.reporter import generate_markdown_report

init()

def main():
    if len(sys.argv) < 2:
        target = input("Введите URL для сканирования: ")
    else:
        target = sys.argv[1]

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print(f"\nЗапуск Web Scanner для: {target}")
    print("-" * 50)

    session = create_session()
    all_findings = []

    # 1. Заголовки
    print("[1/3] Проверка Security Headers...")
    try:
        headers_results = check_security_headers(session, target)
        all_findings.extend(headers_results)
        for res in headers_results:
            if res['status'] == 'MISSING':
                print(f" [!] {res['header']}: {res['info']}")
            elif res['status'] == 'ERROR':
                print(f" [X] Ошибка подключения")
            else:
                print(f" [+] {res['header']}: OK")
    except Exception:
        print(" [X] Ошибка при проверке заголовков")

    # 2. Технологии
    print("\n[2/3] Определение технологий...")
    try:
        tech_results = check_tech_stack(session, target)
        all_findings.extend(tech_results)
        for res in tech_results:
            if res['status'] == 'DETECTED':
                print(f" [+] {res['item']}: {res['info']}")
            elif res['status'] == 'HIDDEN':
                print(f" [?] {res['item']}: {res['info']}")
            else:
                print(f" [X] {res['item']}: Ошибка определения")
    except Exception:
        print(" [X] Ошибка при определении технологий")

    # 3. Открытые файлы
    print("\n[3/3] Поиск чувствительных файлов...")
    try:
        files_results = check_exposed_files(session, target)
        all_findings.extend(files_results)
        
        if files_results:
            for res in files_results:
                if res['status'] == 'FOUND':
                    color = Fore.RED if res['severity'] == 'Critical' else Fore.YELLOW
                    print(f" [!] {res['file']}: {res['info']}")
                elif res['status'] == 'FORBIDDEN':
                    print(f" [?] {res['file']}: доступ запрещён")
        else:
            print(" [+] Чувствительные файлы не найдены")
    except Exception:
        print(" [X] Ошибка при проверке файлов")

    # 4. Отчёт
    print("\n[4/4] Генерация отчёта...")
    report_file = generate_markdown_report(target, all_findings)
    print(f" Отчёт сохранён: {report_file}")

    # Итог
    critical = len([f for f in all_findings if f.get('severity') in ['Critical', 'High'] and f.get('status') in ['MISSING', 'FOUND', 'DETECTED']])
    print("\n" + "=" * 50)
    if critical > 0:
        print(f"Найдено проблем высокого риска: {critical}")
    else:
        print("Критических уязвимостей не обнаружено")
    print(f"Всего проверок выполнено: {len(all_findings)}")

if __name__ == "__main__":
    main()