# main.py
import sys
from colorama import init, Fore, Style
from core.session import create_session
from checks.headers import check_security_headers
from checks.exposed_files import check_exposed_files
from core.reporter import generate_markdown_report

init()

def main():
    if len(sys.argv) < 2:
        target = input("🌐 Введите URL для сканирования: ")
    else:
        target = sys.argv[1]

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print(f"\n{Fore.CYAN}🚀 Запуск Web Scanner для: {target}{Style.RESET_ALL}")
    print("-" * 50)

    session = create_session()
    all_findings = []

    # 1. Проверка заголовков
    print(f"{Fore.YELLOW}[1/2] Проверка Security Headers...{Style.RESET_ALL}")
    try:
        headers_results = check_security_headers(session, target)
        all_findings.extend(headers_results)
        for res in headers_results:
            if res['status'] == 'MISSING':
                print(f"{Fore.RED} [!] {res['header']}: {res['info']}{Style.RESET_ALL}")
            elif res['status'] == 'ERROR':
                print(f"{Fore.RED} [X] Ошибка подключения: {res['info'][:50]}...{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN} [+] {res['header']}: OK{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[X] Ошибка при проверке заголовков: {e}{Style.RESET_ALL}")

    # 2. Проверка открытых файлов
    print(f"\n{Fore.YELLOW}[2/2] Поиск чувствительных файлов...{Style.RESET_ALL}")
    try:
        files_results = check_exposed_files(session, target)
        all_findings.extend(files_results)
        
        if files_results:
            for res in files_results:
                if res['status'] == 'FOUND':
                    severity_color = Fore.RED if res['severity'] == 'Critical' else Fore.YELLOW
                    print(f"{severity_color} [!] {res['file']}: {res['info']}{Style.RESET_ALL}")
                elif res['status'] == 'FORBIDDEN':
                    print(f"{Fore.CYAN} [?] {res['file']}: доступ запрещён{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN} [+] Чувствительные файлы не найдены{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[X] Ошибка при проверке файлов: {e}{Style.RESET_ALL}")

    # 3. Генерация отчёта
    print(f"\n{Fore.YELLOW}[3/3] Генерация отчёта...{Style.RESET_ALL}")
    report_file = generate_markdown_report(target, all_findings)
    print(f"{Fore.GREEN} ✅ Отчёт сохранён: {report_file}{Style.RESET_ALL}")

    # Итоговая статистика
    critical = len([f for f in all_findings if f.get('severity') == 'Critical' and f.get('status') in ['MISSING', 'FOUND']])
    print("\n" + "=" * 50)
    if critical > 0:
        print(f"{Fore.RED}⚠️  Найдено критических уязвимостей: {critical}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}✅ Критических уязвимостей не обнаружено{Style.RESET_ALL}")
    print(f"📊 Всего проверок: {len(all_findings)}")

if __name__ == "__main__":
    main()