# --- НЕОБХОДИМЫЕ УСТАНОВКИ ---
#
# 1. Убедись, что main.py уже запущен! (uvicorn main:app --reload)
# 2. Установи streamlit:
#    pip install streamlit requests
#
# 3. Запуск (в НОВОМ, втором терминале):
#    streamlit run dashboard.py
#
# ---------------------------------

import streamlit as st
import requests
import pandas as pd

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

# --- Функции API ---

def login(username, password):
    """Попытка входа в API"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/token",
            data={"username": username, "password": password}
        )
        if response.status_code == 200:
            tokens = response.json()
            st.session_state.access_token = tokens["access_token"]
            st.session_state.username = username
            st.session_state.error = ""
            st.session_state.success_msg = ""
            st.rerun()
        elif response.status_code == 429:
             st.session_state.error = "⛔ Слишком много попыток! (Rate Limit сработал)"
        else:
            st.session_state.error = "❌ Неверный логин или пароль"
    except requests.exceptions.ConnectionError:
        st.session_state.error = "🔌 Не удается подключиться к API. (main.py запущен?)"

def register(username, password):
    """Регистрация нового пользователя"""
    try:
        # По умолчанию регистрируем обычного user, не админа
        response = requests.post(
            f"{API_BASE_URL}/register",
            json={"username": username, "password": password, "role": "user"}
        )
        if response.status_code == 200:
            st.session_state.success_msg = f"✅ Пользователь '{username}' создан! Теперь войдите."
            st.session_state.error = ""
        elif response.status_code == 400:
            st.session_state.error = "❌ Такой пользователь уже существует."
        else:
            st.session_state.error = f"Ошибка регистрации: {response.text}"
    except requests.exceptions.ConnectionError:
        st.session_state.error = "🔌 Не удается подключиться к API."

def logout():
    """Выход из системы"""
    st.session_state.access_token = ""
    st.session_state.username = ""
    st.session_state.error = ""
    st.session_state.success_msg = ""
    st.rerun()

def get_auth_headers():
    return {"Authorization": f"Bearer {st.session_state.access_token}"}

def get_config_flags():
    if not st.session_state.access_token: return None
    try:
        response = requests.get(f"{API_BASE_URL}/admin/config", headers=get_auth_headers())
        if response.status_code == 200: return response.json()
        elif response.status_code == 401: logout()
        return None
    except: return None

def toggle_feature(feature_name: str):
    try:
        response = requests.post(f"{API_BASE_URL}/admin/toggle/{feature_name}", headers=get_auth_headers())
        if response.status_code == 200: st.toast(f"Флаг '{feature_name}' переключен!", icon="✅")
        elif response.status_code == 401: logout()
    except: pass

def get_security_logs():
    if not st.session_state.access_token: return None
    try:
        response = requests.get(f"{API_BASE_URL}/admin/logs", headers=get_auth_headers())
        if response.status_code == 200: return response.json()
        elif response.status_code == 401: logout()
        return None
    except: return None


# --- ИНТЕРФЕЙС ---

# 1. ЭКРАН АВТОРИЗАЦИИ (Если нет токена)
if not st.session_state.access_token:
    st.set_page_config(page_title="Admin Login", layout="centered")
    
    st.title("🔐 Вход в систему")
    st.caption("Авторизуйтесь, чтобы управлять защитой API.")

    # Вкладки: Вход / Регистрация
    tab1, tab2 = st.tabs(["Вход", "Регистрация"])

    with tab1:
        with st.form("login_form"):
            username = st.text_input("Имя пользователя", value="admin")
            password = st.text_input("Пароль", type="password", value="admin123")
            submitted = st.form_submit_button("Войти", use_container_width=True)
            
            if submitted:
                login(username, password)

    with tab2:
        with st.form("register_form"):
            st.caption("Создайте нового пользователя (роль: User)")
            new_user = st.text_input("Придумайте логин")
            new_pass = st.text_input("Придумайте пароль", type="password")
            reg_submitted = st.form_submit_button("Зарегистрироваться", use_container_width=True)
            
            if reg_submitted:
                if new_user and new_pass:
                    register(new_user, new_pass)
                else:
                    st.error("Заполните все поля")

    # Сообщения об ошибках/успехе
    if st.session_state.error:
        st.error(st.session_state.error)
    if st.session_state.success_msg:
        st.success(st.session_state.success_msg)

# 2. ГЛАВНАЯ ПАНЕЛЬ (Если есть токен)
else:
    st.set_page_config(page_title="API Security Dashboard", layout="wide")
    
    with st.sidebar:
        st.title(f"👋 Привет, {st.session_state.username}")
        st.button("Выйти из системы", on_click=logout, use_container_width=True)
        st.divider()
        st.page_link("http://127.0.0.1:8000/docs", label="Документация API (FastAPI)", icon="📄")

    st.title("🛡️ Панель Управления Безопасностью API")
    st.divider()

    # --- Переключатели ---
    st.header("⚙️ Переключатели Защиты")
    config_flags = get_config_flags()
    
    if config_flags:
        cols = st.columns(3)
        states = {flag['feature']: flag['enabled'] for flag in config_flags}
        
        with cols[0]:
            st.subheader("IDOR (BOLA)")
            st.toggle("Защита от IDOR", value=states.get("idor_protection", False), key="toggle_idor", on_change=toggle_feature, args=("idor_protection",))
            st.caption("Блокирует доступ к чужим заметкам.")

        with cols[1]:
            st.subheader("SQL Injection")
            st.toggle("Защита от SQLi", value=states.get("sqli_protection", False), key="toggle_sqli", on_change=toggle_feature, args=("sqli_protection",))
            st.caption("Включает безопасные ORM запросы.")

        with cols[2]:
            st.subheader("Brute-force")
            st.toggle("Rate Limiter", value=states.get("rate_limit", False), key="toggle_rate_limit", on_change=toggle_feature, args=("rate_limit",))
            st.caption("Блокирует частые запросы (5 в минуту).")
    else:
        st.warning("⚠️ Не удалось загрузить настройки (возможно, токен истек или у вас нет прав админа).")

    st.divider()
    
    # --- Логи ---
    col_log_1, col_log_2 = st.columns([8, 2])
    with col_log_1:
        st.header("📜 Журнал Событий")
    with col_log_2:
        if st.button("🔄 Обновить логи", use_container_width=True):
            st.rerun()

    logs_data = get_security_logs()
    if logs_data:
        df = pd.DataFrame(logs_data)
        df_display = df[['timestamp', 'ip', 'user', 'attack_type', 'payload', 'result']]
        df_display['timestamp'] = pd.to_datetime(df_display['timestamp']).dt.strftime('%H:%M:%S')
        
        st.dataframe(
            df_display, 
            use_container_width=True,
            column_config={
                "timestamp": "Время",
                "result": st.column_config.TextColumn("Результат"),
                "attack_type": "Тип Атаки",
                "payload": "Данные (Payload)"
            }
        )
    else:
        st.info("Логов пока нет.")