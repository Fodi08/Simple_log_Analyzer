import re

# 1. Функция для разбора одной строки 
def parse_line(line):
    pattern = r'^(\d+\.\d+\.\d+\.\d+) .* "(.*?)" (\d{3})'
    match = re.search(pattern, line)
    if match:
        return {
            'ip': match.group(1),
            'request': match.group(2),
            'status': match.group(3)
        }
    return None

def analyze_file(filename):
    print(f"Начинаем анализ файла: {filename}...")
    
    # Словари для подсчёта: {IP: количество попыток}
    failed_logins = {}
    sql_injections = {}
    xss_attempts = {}
    dir_traversal = {}
    vuln_scanning = {}
    admin_backup = {}
    
    # Шаблоны для обнаружения
    xss_patterns = ['<script', 'onerror=', 'javascript:', 'alert(']
    traversal_patterns = ['../', '..%2f', '..\\', '/etc/passwd', '/etc/shadow']
    scan_patterns = ['/wp-login', '/wp-admin', '/phpmyadmin', '/xmlrpc.php', '/cgi-bin/', '/scripts/', '/.env', '/.git']
    admin_backup_patterns = ['/backup', '/dump.sql', '/database.sql', '/.htaccess', '/.htpasswd', '/readme.html', '/license.txt', '/wp-content', '/wp-includes']
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                data = parse_line(line)
                if not data:
                    continue
                
                ip = data['ip']
                req = data['request'].lower()
                status = data['status']
                
                # 1. Brute Force
                if status == '401':
                    failed_logins[ip] = failed_logins.get(ip, 0) + 1
                    
                # 2. SQL Injection
                if any(p in req for p in ['union', 'or 1=1', 'select', '; drop', 'exec xp_']):
                    sql_injections[ip] = sql_injections.get(ip, 0) + 1
                    
                # 3. XSS-атаки
                if any(p in req for p in xss_patterns):
                    xss_attempts[ip] = xss_attempts.get(ip, 0) + 1
                    
                # 4. Directory Traversal
                if any(p in req for p in traversal_patterns):
                    dir_traversal[ip] = dir_traversal.get(ip, 0) + 1
                    
                # 5. Сканирование уязвимостей
                if any(p in req for p in scan_patterns):
                    vuln_scanning[ip] = vuln_scanning.get(ip, 0) + 1
                    
                # 6. Поиск админок/бекапов
                if any(p in req for p in admin_backup_patterns):
                    admin_backup[ip] = admin_backup.get(ip, 0) + 1

    except FileNotFoundError:
        print(f"Ошибка: Файл {filename} не найден.")
        return

    # --- Вывод отчёта ---
    print("\n" + "="*40)
    print("ПОЛНЫЙ ОТЧЕТ ПО БЕЗОПАСНОСТИ")
    print("="*40)
    
    # Вспомогательная функция для красивого вывода разделов
    def print_section(title, data_dict):
        total = sum(data_dict.values())
        print(f"\n{title}: {total}")
        if data_dict:
            sorted_items = sorted(data_dict.items(), key=lambda x: x[1], reverse=True)
            for ip, count in sorted_items:
                print(f"    {ip} ({count} попыток)")
                
    print_section("Ошибки входа (Brute-Force)", failed_logins)
    print_section("SQL-инъекции", sql_injections)
    print_section("XSS-атаки", xss_attempts)
    print_section("Directory Traversal", dir_traversal)
    print_section("Сканирование уязвимостей", vuln_scanning)
    print_section("Поиск админок/бекапов", admin_backup)
    
    total_threats = sum(failed_logins.values()) + sum(sql_injections.values()) + sum(xss_attempts.values()) + sum(dir_traversal.values()) + sum(vuln_scanning.values()) + sum(admin_backup.values())
    print(f"\n Всего зафиксировано угроз: {total_threats}")
# Запуск анализа 
analyze_file('access.log')