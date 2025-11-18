# --- НЕОБХОДИМЫЕ УСТАНОВКИ ---
#
# 1. Убедись, что main.py уже запущен! (uvicorn main:app --reload)
# 2. (Опционально) Убедись, что dashboard.py запущен, чтобы видеть магию!
# 3. Установи 'requests' и 'rich' (для красивого вывода):
#    pip install requests rich
#
# 4. Запуск (в ТРЕТЬЕМ терминале):
#    python attack_demo.py
#
# ---------------------------------

import requests
import time
from rich.console import Console

# Используем 'rich' для красивого цветного вывода в терминале
console = Console()

# --- Конфигурация ---
API_BASE_URL = "http://127.0.0.1:8000"

# --- ID Тестовых Данных ---
# (Основано на том, как main.py создает юзеров при запуске)
# alice = user_id 2
# bob = user_id 3
# alice's note = note_id 1
# bob's public note = note_id 2
# bob's SECRET note = note_id 3
VICTIM_NOTE_ID = 3


# --- Вспомогательные Функции ---

def login(username, password):
    """Помощник: Логинится и возвращает токены"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/token",
            data={"username": username, "password": password}
        )
        response.raise_for_status() # Вызовет ошибку, если status != 2xx
        return response.json()
    except requests.exceptions.HTTPError as e:
        console.print(f"[bold red]Ошибка входа для {username}: {e.response.status_code} {e.response.json()}[/bold red]")
        return None
    except requests.exceptions.ConnectionError:
        console.print(f"[bold red]Не удается подключиться к API. {API_BASE_URL} запущен?[/bold red]")
        exit(1) # Критическая ошибка, выходим

def admin_toggle_feature(admin_token: str, feature_name: str, enable: bool):
    """
    Помощник: Включает или выключает защиту.
    Сначала проверяет текущее состояние, чтобы избежать лишних переключений.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # 1. Проверить текущее состояние
    try:
        resp_get = requests.get(f"{API_BASE_URL}/admin/config", headers=headers)
        resp_get.raise_for_status()
        flags = resp_get.json()
        
        current_state = next(
            (f['enabled'] for f in flags if f['feature'] == feature_name), 
            None
        )
        
        if current_state is None:
            console.print(f"[red]Ошибка: Флаг '{feature_name}' не найден на сервере.[/red]")
            return
            
        # 2. Переключить, только если состояние не совпадает
        if current_state == enable:
            console.print(f"[cyan]... {feature_name} уже {'ON' if enable else 'OFF'}.[/cyan]")
            return

        resp_post = requests.post(f"{API_BASE_URL}/admin/toggle/{feature_name}", headers=headers)
        resp_post.raise_for_status()
        console.print(f"[bold green]... {feature_name} успешно переключен на {'ON' if enable else 'OFF'}.[/bold green]")
        
    except requests.exceptions.HTTPError as e:
        console.print(f"[red]Ошибка при переключении '{feature_name}': {e.response.text}[/red]")

# --- Основной Скрипт Демонстрации ---

def run_demo():
    
    console.rule("[bold]🚀 Запуск Демонстрации Безопасности API[/bold]", style="white")
    
    # --- 1. Вход ---
    console.rule("[1] Аутентификация", style="cyan")
    
    admin_auth = login("admin", "admin123")
    if not admin_auth: return
    admin_token = admin_auth["access_token"]
    console.print("[green]✅ Вход от имени [bold]Администратора[/bold] выполнен.[/green]")
    
    alice_auth = login("alice", "alice123")
    if not alice_auth: return
    alice_token = alice_auth["access_token"]
    console.print("[green]✅ Вход от имени [bold]Alice (Атакующий)[/bold] выполнен.[/green]")

    # --- 2. СЦЕНАРИЙ: IDOR (BOLA) ---
    console.rule(f"[2] Сценарий: IDOR (Атака на Заметку ID: {VICTIM_NOTE_ID})", style="magenta")

    # --- 2a. Уязвимый режим (Защита ВЫКЛ) ---
    console.print("[bold yellow]A. Тест в УЯЗВИМОМ режиме (Защита ВЫКЛ):[/bold yellow]")
    admin_toggle_feature(admin_token, "idor_protection", enable=False)
    
    console.print(f"[yellow]... Alice (user 2) пытается украсть заметку Bob (user 3) с ID={VICTIM_NOTE_ID}...[/yellow]")
    headers_alice = {"Authorization": f"Bearer {alice_token}"}
    r_idor_vuln = requests.get(f"{API_BASE_URL}/notes/{VICTIM_NOTE_ID}", headers=headers_alice)
    
    if r_idor_vuln.status_code == 200:
        console.print(f"[bold red]🔥 АТАКА IDOR УСПЕШНА (200 OK):[/bold red] Alice получила данные:")
        console.print(r_idor_vuln.json())
    else:
        console.print(f"[green]... Атака не удалась (Код: {r_idor_vuln.status_code})[/green]")

    # --- 2b. Безопасный режим (Защита ВКЛ) ---
    console.print("\n[bold green]B. Тест в БЕЗОПАСНОМ режиме (Защита ВКЛ):[/bold green]")
    admin_toggle_feature(admin_token, "idor_protection", enable=True)
    
    console.print(f"[yellow]... Alice повторяет атаку на Заметку ID={VICTIM_NOTE_ID}...[/yellow]")
    r_idor_sec = requests.get(f"{API_BASE_URL}/notes/{VICTIM_NOTE_ID}", headers=headers_alice)
    
    if r_idor_sec.status_code in [404, 403]:
        console.print(f"[bold green]🛡️ АТАКА IDOR ЗАБЛОКИРОВАНА (Код: {r_idor_sec.status_code}):[/bold green]")
        console.print(r_idor_sec.json())
    else:
        console.print(f"[red]... Ошибка: Атака прошла (Код: {r_idor_sec.status_code})[/red]")

    # --- 3. СЦЕНАРИЙ: SQL INJECTION ---
    sqli_payload = "' OR '1'='1"
    console.rule(f"[3] Сценарий: SQL INJECTION (Payload: \"{sqli_payload}\")", style="magenta")

    # --- 3a. Уязвимый режим (Защита ВЫКЛ) ---
    console.print("[bold yellow]A. Тест в УЯЗВИМОМ режиме (Защита ВЫКЛ):[/bold yellow]")
    admin_toggle_feature(admin_token, "sqli_protection", enable=False)
    
    console.print(f"[yellow]... Alice отправляет SQLi payload в эндпоинт /search ...[/yellow]")
    r_sqli_vuln = requests.get(
        f"{API_BASE_URL}/search", 
        headers=headers_alice,
        params={"query": sqli_payload}
    )
    
    if r_sqli_vuln.status_code == 200:
        data = r_sqli_vuln.json()
        console.print(f"[bold red]🔥 АТАКА SQLi УСПЕШНА (200 OK):[/bold red] Сервер вернул {len(data)} записей (включая чужие):")
        console.print(data)
    else:
        console.print(f"[green]... Атака не удалась (Код: {r_sqli_vuln.status_code})[/green]")

    # --- 3b. Безопасный режим (Защита ВКЛ) ---
    console.print("\n[bold green]B. Тест в БЕЗОПАСНОМ режиме (Защита ВКЛ):[/bold green]")
    admin_toggle_feature(admin_token, "sqli_protection", enable=True)
    
    console.print(f"[yellow]... Alice повторяет атаку SQLi...[/yellow]")
    r_sqli_sec = requests.get(
        f"{API_BASE_URL}/search", 
        headers=headers_alice,
        params={"query": sqli_payload}
    )
    
    if r_sqli_sec.status_code == 200:
        data = r_sqli_sec.json()
        console.print(f"[bold green]🛡️ АТАКА SQLi ЗАБЛОКИРОВАНА (200 OK):[/bold green] Сервер вернул {len(data)} записей (пустой список).")
        console.print(data)
    else:
        console.print(f"[red]... Ошибка: Атака прошла (Код: {r_sqli_sec.status_code})[/red]")

    # --- 4. СЦЕНАРИЙ: BRUTE-FORCE (RATE LIMIT) ---
    console.rule(f"[4] Сценарий: BRUTE-FORCE (Атака на /token)", style="magenta")

    # --- 4a. Уязвимый режим (Защита ВЫКЛ) ---
    console.print("[bold yellow]A. Тест в УЯЗВИМОМ режиме (Rate Limit ВЫКЛ):[/bold yellow]")
    admin_toggle_feature(admin_token, "rate_limit", enable=False)
    
    console.print(f"[yellow]... Атакующий отправляет 7 неверных запросов на /token...[/yellow]")
    blocked_vuln = False
    for i in range(7):
        r_bf_vuln = requests.post(f"{API_BASE_URL}/token", data={"username": "alice", "password": f"wrong{i}"})
        console.print(f"  Попытка {i+1}: Статус {r_bf_vuln.status_code}")
        if r_bf_vuln.status_code == 429:
            blocked_vuln = True
            
    if not blocked_vuln:
        console.print("[bold red]🔥 АТАКА BRUTE-FORCE УСПЕШНА:[/bold red] Сервер не заблокировал запросы (не было 429).")
    else:
        console.print("[green]... Ошибка: Сервер заблокировал запросы (это не должно было случиться).[/green]")

    # --- 4b. Безопасный режим (Защита ВКЛ) ---
    console.print("\n[bold green]B. Тест в БЕЗОПАСНОМ режиме (Rate Limit ВКЛ):[/bold green]")
    console.print("[grey]... (Ждем 10 секунд, чтобы простой in-memory лимитер сбросился, если вдруг он остался от прошлых тестов)[/grey]")
    # time.sleep(10) # В main.py лимитер сбрасывается через 60с, но для демо мы его просто включим
    
    admin_toggle_feature(admin_token, "rate_limit", enable=True)
    
    console.print(f"[yellow]... Атакующий отправляет 7 неверных запросов на /token...[/yellow]")
    blocked_sec = False
    for i in range(7):
        r_bf_sec = requests.post(f"{API_BASE_URL}/token", data={"username": "alice", "password": f"wrong{i}"})
        console.print(f"  Попытка {i+1}: Статус {r_bf_sec.status_code}")
        # Лимит по умолчанию = 5 запросов
        if r_bf_sec.status_code == 429:
            blocked_sec = True
            console.print(f"  [bold]Попытка {i+1}: Статус {r_bf_sec.status_code} (Too Many Requests)[/bold]")
            break
            
    if blocked_sec:
        console.print("[bold green]🛡️ АТАКА BRUTE-FORCE ЗАБЛОКИРОВАНА:[/bold green] Сервер вернул 429 (Too Many Requests).")
    else:
        console.print("[red]... Ошибка: Сервер НЕ заблокировал запросы.[/red]")

    # --- 5. Завершение ---
    console.rule("[5] Сброс и Завершение", style="cyan")
    console.print("[yellow]... Сброс всех флагов в состояние OFF для следующего демо...[/yellow]")
    admin_toggle_feature(admin_token, "idor_protection", enable=False)
    admin_toggle_feature(admin_token, "sqli_protection", enable=False)
    admin_toggle_feature(admin_token, "rate_limit", enable=False)
    
    console.rule("[bold green]✅ ДЕМОНСТРАЦИЯ ЗАВЕРШЕНА[/bold green]", style="white")
    console.print("[bold]Пожалуйста, проверьте 📜 Журнал Событий Безопасности 📜 в админ-панели (Streamlit)![/bold]")


if __name__ == "__main__":
    run_demo()