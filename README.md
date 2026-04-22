# Анализатор логов (Python) /Ru/

Простой анализатор логов веб-сервера для обнаружения базовых угроз безопасности. Разработан в рамках учебного проекта для изучения принципов мониторинга и детектирования атак.

## Что детектирует
- **Brute Force / Credential Stuffing**: Множественные запросы с кодом `401` (Unauthorized) с одного IP-адреса.
- **SQL Injection**: Попытки внедрения SQL-команд в параметры URL (`UNION`, `OR 1=1`, `SELECT`).
- **XSS Attempts**: Сценарии и обработчики событий (`<script>`, `onerror=`, `alert()`).
- **Directory Traversal**: Последовательности прохождения пути (`../`, `..%2f`) and sensitive file access (`/etc/passwd`).
- **Vulnerability Scanning**: Запросы к общим целевым объектам сканирования (`/wp-login`, `/phpmyadmin`, `/.env`, `/cgi-bin/`).
- **Admin & Backup Discovery**: Поиск резервных копий и настроек (`/backup.sql`, `/.htaccess`, `/wp-content/`).

## Структура проекта
├── main.p # Основной скрипт анализа
├── access.log # Пример логов для тестирования
└── README.m # Документация

## Как запустить
1. Убедитесь, что установлен Python 3.x
2. Положите файл логов в формате Apache/Nginx Combined рядом с `main.py`
3. Запустите скрипт:
```bash
python main.py
```
## Как работает
1. Скрипт читает лог построчно (оптимизация памяти для больших файлов).
2. С помощью регулярных выражений извлекает: IP, HTTP-запрос, Статус-код.
3. Применяет правила детектирования:
    status == 401 → добавляет IP в список подозрительных
    Наличие SQL-ключевых слов в URL → флажит как инъекцию
4. Выводит структурированный отчет в консоль.

## Технологии
* Python 3
* Regular Expressions (re)
* File I/O с потоковым чтением

Автор: Fodi



# Log Security Analyzer (Python) /EN/

A simple web server log analyzer for detecting basic security threats. Developed as an educational project to study monitoring and attack detection principles.

## Detection Capabilities
- **Brute Force / Credential Stuffing**: Multiple `401` responses from a single IP.
- **SQL Injection**: Payloads like `UNION`, `OR 1=1`, `SELECT`, `DROP` in URL parameters.
- **XSS Attempts**: Scripts and event handlers (`<script>`, `onerror=`, `alert()`).
- **Directory Traversal**: Path traversal sequences (`../`, `..%2f`) and sensitive file access (`/etc/passwd`).
- **Vulnerability Scanning**: Requests to common scanner targets (`/wp-login`, `/phpmyadmin`, `/.env`, `/cgi-bin/`).
- **Admin & Backup Discovery**: Probing for backups and configs (`/backup.sql`, `/.htaccess`, `/wp-content/`).

## Project Structure
├── main.py          # Main analysis script
├── access.log       # Sample logs for testing
└── README.md        # Documentation

## How to Run
1. Ensure Python 3.x is installed.
2. Place an Apache/Nginx Combined format log file next to main.py.
3. Run the script:

```bash
python main.py
```
## How It Works
1. The script reads the log line-by-line (memory-optimized for large files).
2. Uses regular expressions to extract: IP address, HTTP request, and Status code.
3. Applies detection rules:
    status == 401 → adds the IP to a suspicious list
    Presence of SQL keywords in the URL → flags as an injection attempt
5. Outputs a structured security report to the console.

## Technologies
* Python 3
* Regular Expressions (re module)
* Streaming File I/O

Author: Fodi
