import requests
from rich.console import Console

console = Console()
API_BASE_URL = "http://127.0.0.1:8000"

# --- Настройка цветов ---
def print_success(msg): console.print(f"[bold red]🔥 {msg}[/bold red]") # Красный, т.к. для хакера успех - это плохо для нас
def print_blocked(msg): console.print(f"[bold green]🛡️ {msg}[/bold green]") # Зеленый, т.к. защита сработала
def print_info(msg): console.print(f"[cyan]{msg}[/cyan]")

def run_attacks():
    console.rule("[bold]💀 ЗАПУСК АТАКИ ХАКЕРА[/bold]")

    # 1. Логинимся как злоумышленник (Alice)
    try:
        auth = requests.post(f"{API_BASE_URL}/token", data={"username": "alice", "password": "alice123"})
        if auth.status_code != 200:
            console.print("[red]Ошибка входа Alice. Проверь сервер.[/red]")
            return
        token = auth.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
    except:
        console.print("[red]Сервер не отвечает![/red]")
        return

    # --- АТАКА 1: IDOR ---
    console.print("\n[bold]1. Попытка IDOR (чтение чужой заметки ID=3)[/bold]")
    r = requests.get(f"{API_BASE_URL}/notes/3", headers=headers)
    
    if r.status_code == 200:
        data = r.json()
        print_success(f"УСПЕХ! Украдены данные: {data['content']}")
    elif r.status_code in [403, 404]:
        print_blocked(f"ОТКАЗ! Сервер ответил: {r.status_code} (Not Found/Forbidden)")
    else:
        print_info(f"Странный ответ: {r.status_code}")

    # --- АТАКА 2: SQL Injection ---
    console.print("\n[bold]2. Попытка SQL Injection (поиск: ' OR '1'='1)[/bold]")
    sqli_payload = "' OR '1'='1"
    r = requests.get(f"{API_BASE_URL}/search", headers=headers, params={"query": sqli_payload})
    
    # Если вернулся список и он НЕ пустой — значит, мы вытащили лишнее
    if r.status_code == 200:
        data = r.json()
        if len(data) > 0:
            print_success(f"УСПЕХ! База слита, получено записей: {len(data)}")
        else:
            print_blocked("ОТКАЗ! Поиск вернул 0 записей (SQLi не прошла).")
    elif r.status_code == 500:
        print_info("ОШИБКА СЕРВЕРА (500). SQL запрос сломал базу, но данные не украдены.")
    else:
        print_blocked(f"ОТКАЗ! Код: {r.status_code}")

    # --- АТАКА 3: Brute-force ---
    console.print("\n[bold]3. Попытка Brute-force (спам запросами)[/bold]")
    blocked = False
    for i in range(1, 6):
        r = requests.post(f"{API_BASE_URL}/token", data={"username": "alice", "password": f"badpass{i}"})
        if r.status_code == 429:
            print_blocked(f"Попытка {i}: ЗАБЛОКИРОВАНО (429 Too Many Requests)")
            blocked = True
            break
        else:
            print_success(f"Попытка {i}: Прошла (код {r.status_code})")
            
    if not blocked:
        print_success("ИТОГ: Брутфорс удался, нас не забанили.")

if __name__ == "__main__":
    run_attacks()