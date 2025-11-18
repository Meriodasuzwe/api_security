import streamlit as st
import requests
import pandas as pd
import time

# --- Конфигурация ---
API_BASE_URL = "http://127.0.0.1:8000"

# --- Инициализация Session State ---
if "access_token" not in st.session_state:
    st.session_state.access_token = ""
if "username" not in st.session_state:
    st.session_state.username = ""
if "error" not in st.session_state:
    st.session_state.error = ""
if "success_msg" not in st.session_state:
    st.session_state.success_msg = ""

# --- Вспомогательные функции ---

def get_auth_headers():
    return {"Authorization": f"Bearer {st.session_state.access_token}"}

def login_process(username, password):
    """Логика входа"""
    try:
        response = requests.post(f"{API_BASE_URL}/token", data={"username": username, "password": password})
        if response.status_code == 200:
            tokens = response.json()
            st.session_state.access_token = tokens["access_token"]
            st.session_state.username = username
            st.session_state.error = ""
            return True # Успех
        elif response.status_code == 429:
             st.session_state.error = "⛔ Слишком много попыток! (Rate Limit)"
        else:
            st.session_state.error = "❌ Неверный логин или пароль"
    except requests.exceptions.RequestException: # Ловим ТОЛЬКО ошибки сети
        st.session_state.error = "🔌 API недоступен (проверьте uvicorn)"
    return False

def register_process(username, password):
    """Логика регистрации"""
    try:
        response = requests.post(f"{API_BASE_URL}/register", json={"username": username, "password": password, "role": "user"})
        if response.status_code == 200:
            st.session_state.success_msg = f"✅ Пользователь '{username}' создан! Теперь войдите."
            st.session_state.error = ""
        else:
            st.session_state.error = f"Ошибка: {response.text}"
    except requests.exceptions.RequestException:
        st.session_state.error = "🔌 API недоступен"

def logout_process():
    st.session_state.access_token = ""
    st.session_state.username = ""
    st.rerun()

# --- Функции запросов данных ---
def get_config_flags():
    try:
        return requests.get(f"{API_BASE_URL}/admin/config", headers=get_auth_headers()).json()
    except: return None

def toggle_feature(feature):
    try:
        requests.post(f"{API_BASE_URL}/admin/toggle/{feature}", headers=get_auth_headers())
        # Не делаем rerun здесь, Streamlit сам обновит состояние при клике
    except: pass

def get_logs():
    try:
        return requests.get(f"{API_BASE_URL}/admin/logs", headers=get_auth_headers()).json()
    except: return None

def get_my_notes():
    try:
        res = requests.get(f"{API_BASE_URL}/notes", headers=get_auth_headers())
        return res.json() if res.status_code == 200 else []
    except: return []

def create_note(title, content):
    try:
        requests.post(f"{API_BASE_URL}/notes", json={"title": title, "content": content}, headers=get_auth_headers())
        st.toast("Заметка создана!", icon="✅")
        time.sleep(0.5)
        st.rerun()
    except: pass

def try_steal_admin_note():
    try:
        res = requests.get(f"{API_BASE_URL}/notes/1", headers=get_auth_headers())
        return res.status_code, res.json()
    except: return 0, {}

def try_sqli_search(query):
    try:
        res = requests.get(f"{API_BASE_URL}/search", params={"query": query}, headers=get_auth_headers())
        return res.status_code, res.json()
    except: return 0, []


# --- ИНТЕРФЕЙС ---

if not st.session_state.access_token:
    # === ЭКРАН ВХОДА ===
    st.set_page_config(page_title="Login", layout="centered")
    st.title("🔐 Вход в систему")
    
    tab1, tab2 = st.tabs(["Вход", "Регистрация"])
    
    with tab1:
        with st.form("login"):
            u = st.text_input("Логин", value="admin")
            p = st.text_input("Пароль", type="password", value="admin123")
            # Кнопка отправки формы
            if st.form_submit_button("Войти", use_container_width=True):
                if login_process(u, p):
                    st.rerun() # Делаем реран ТОЛЬКО если успех, и ВНЕ блока try/except

    with tab2:
        with st.form("reg"):
            u = st.text_input("Новый логин")
            p = st.text_input("Новый пароль", type="password")
            if st.form_submit_button("Создать аккаунт", use_container_width=True):
                register_process(u, p)
    
    if st.session_state.error: st.error(st.session_state.error)
    if st.session_state.success_msg: st.success(st.session_state.success_msg)

else:
    # === ПАНЕЛЬ УПРАВЛЕНИЯ ===
    st.set_page_config(page_title="Dashboard", layout="wide")
    
    with st.sidebar:
        st.title(f"👤 {st.session_state.username}")
        if st.session_state.username == "admin":
            st.badge("ADMIN MODE")
        else:
            st.badge("USER MODE")
        
        # Исправлена кнопка выхода (убрали callback, сделали прямой вызов)
        if st.button("Выйти", use_container_width=True):
            logout_process()

    # --- ЛОГИКА ОТОБРАЖЕНИЯ ПО РОЛЯМ ---
    
    # 🔴 ЕСЛИ ЭТО АДМИН 🔴
    if st.session_state.username == "admin":
        st.title("🛡️ Панель Управления Защитой")
        st.info("Режим администратора. Управляйте уязвимостями сервера.")
        
        st.divider()
        st.subheader("⚙️ Тумблеры Защиты")
        flags = get_config_flags()
        if flags:
            c1, c2, c3 = st.columns(3)
            states = {f['feature']: f['enabled'] for f in flags}
            
            # Используем on_change для моментальной реакции
            with c1: 
                st.toggle("IDOR Защита", value=states.get("idor_protection"), key="tg_idor", on_change=toggle_feature, args=("idor_protection",))
                st.caption("Запретить чтение чужих заметок")
            with c2: 
                st.toggle("SQLi Защита", value=states.get("sqli_protection"), key="tg_sqli", on_change=toggle_feature, args=("sqli_protection",))
                st.caption("Использовать безопасный ORM")
            with c3: 
                st.toggle("Rate Limit", value=states.get("rate_limit"), key="tg_rl", on_change=toggle_feature, args=("rate_limit",))
                st.caption("Блокировать брутфорс")
        
        st.divider()
        c_log, c_btn = st.columns([8,2])
        c_log.subheader("📜 Логи Атак")
        if c_btn.button("Обновить"): st.rerun()
        
        logs = get_logs()
        if logs:
            df = pd.DataFrame(logs)
            st.dataframe(df[['timestamp', 'ip', 'user', 'attack_type', 'payload', 'result']], use_container_width=True)
        else:
            st.write("Логов нет.")

    # 🟢 ЕСЛИ ЭТО ОБЫЧНЫЙ ПОЛЬЗОВАТЕЛЬ 🟢
    else:
        st.title(f"Личный кабинет: {st.session_state.username}")
        
        col_left, col_right = st.columns([1, 1])
        
        # ЛЕВАЯ КОЛОНКА
        with col_left:
            st.subheader("📝 Мои Заметки")
            notes = get_my_notes()
            if notes:
                for n in notes:
                    with st.expander(f"📌 {n['title']}"):
                        st.write(n['content'])
                        st.caption(f"ID заметки: {n['id']}")
            else:
                st.info("У вас пока нет заметок.")
            
            st.divider()
            with st.form("add_note"):
                st.caption("Добавить новую заметку")
                t = st.text_input("Заголовок")
                c = st.text_area("Содержание")
                if st.form_submit_button("Сохранить"): create_note(t, c)

        # ПРАВАЯ КОЛОНКА
        with col_right:
            st.subheader("🕵️ Зона Самопроверки (Hacker Zone)")
            st.warning("Здесь вы можете проверить, защищен ли сервер.")
            
            st.write("#### 1. Тест IDOR")
            st.caption("Попытка прочитать Секретную Заметку Админа (ID=1).")
            if st.button("🔥 Украсть заметку Админа"):
                code, data = try_steal_admin_note()
                if code == 200:
                    st.error("УСПЕХ! УЯЗВИМОСТЬ НАЙДЕНА!")
                    st.json(data)
                else:
                    st.success(f"ДОСТУП ЗАПРЕЩЕН (Код {code}). Защита работает.")
            
            st.divider()
            
            st.write("#### 2. Тест SQL Injection")
            st.caption("Поиск с пейлоадом: `' OR '1'='1`")
            if st.button("🔥 Выполнить SQL-инъекцию"):
                code, data = try_sqli_search("' OR '1'='1")
                if code == 200 and len(data) > 0:
                    st.error(f"УСПЕХ! УЯЗВИМОСТЬ НАЙДЕНА! Получено {len(data)} записей.")
                    st.dataframe(data)
                elif code == 500:
                    st.warning("Сервер упал (Ошибка 500). Это тоже уязвимость.")
                else:
                    st.success("БЕЗОПАСНО. Данные не утекли.")