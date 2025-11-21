import streamlit as st
import requests
import pandas as pd
import time
import altair as alt # Библиотека для графиков (встроена в streamlit)

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

# --- Функции ---
def get_auth_headers():
    return {"Authorization": f"Bearer {st.session_state.access_token}"}

def login_process(username, password):
    try:
        response = requests.post(f"{API_BASE_URL}/token", data={"username": username, "password": password})
        if response.status_code == 200:
            tokens = response.json()
            st.session_state.access_token = tokens["access_token"]
            st.session_state.username = username
            st.session_state.error = ""
            return True
        elif response.status_code == 429:
             st.session_state.error = "⛔ Слишком много попыток! (Rate Limit)"
        else:
            st.session_state.error = "❌ Неверный логин или пароль"
    except: st.session_state.error = "🔌 API недоступен"
    return False

def register_process(username, password):
    try:
        response = requests.post(f"{API_BASE_URL}/register", json={"username": username, "password": password, "role": "user"})
        if response.status_code == 200:
            st.session_state.success_msg = f"✅ Пользователь '{username}' создан! Войдите."
            st.session_state.error = ""
        else:
            st.session_state.error = f"Ошибка: {response.text}"
    except: st.session_state.error = "🔌 API недоступен"

def logout_process():
    st.session_state.access_token = ""
    st.session_state.username = ""
    st.rerun()

def get_config_flags():
    try:
        return requests.get(f"{API_BASE_URL}/admin/config", headers=get_auth_headers()).json()
    except: return None

def toggle_feature(feature):
    try:
        requests.post(f"{API_BASE_URL}/admin/toggle/{feature}", headers=get_auth_headers())
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
    st.set_page_config(page_title="Login", layout="centered")
    st.title("🔐 Вход в систему")
    tab1, tab2 = st.tabs(["Вход", "Регистрация"])
    with tab1:
        with st.form("login"):
            u = st.text_input("Логин", value="admin")
            p = st.text_input("Пароль", type="password", value="admin123")
            if st.form_submit_button("Войти", use_container_width=True):
                if login_process(u, p): st.rerun()
    with tab2:
        with st.form("reg"):
            u = st.text_input("Новый логин")
            p = st.text_input("Новый пароль", type="password")
            if st.form_submit_button("Создать аккаунт", use_container_width=True): register_process(u, p)
    if st.session_state.error: st.error(st.session_state.error)
    if st.session_state.success_msg: st.success(st.session_state.success_msg)

else:
    st.set_page_config(page_title="Security Dashboard", layout="wide")
    
    with st.sidebar:
        st.title(f"👤 {st.session_state.username}")
        if st.session_state.username == "admin": st.badge("ADMIN MODE")
        else: st.badge("USER MODE")
        if st.button("Выйти", use_container_width=True): logout_process()

    # --- АДМИН ПАНЕЛЬ (С ГРАФИКОЙ) ---
    if st.session_state.username == "admin":
        st.title("🛡️ Центр Управления Безопасностью")
        
        # 1. Секция Health Score
        st.subheader("Состояние Системы")
        flags = get_config_flags()
        
        if flags:
            states = {f['feature']: f['enabled'] for f in flags}
            
            # Расчет рейтинга безопасности
            score = 0
            if states.get("idor_protection"): score += 35
            if states.get("sqli_protection"): score += 35
            if states.get("rate_limit"): score += 30
            
            # Визуализация прогресс-бара
            progress_color = "red"
            if score > 30: progress_color = "orange"
            if score == 100: progress_color = "green"
            
            col_score, col_toggles = st.columns([1, 2])
            
            with col_score:
                st.metric("Рейтинг Безопасности", f"{score}/100")
                st.progress(score / 100)
                if score == 100: st.success("Система защищена")
                elif score == 0: st.error("Система уязвима!")
                else: st.warning("Частичная защита")

            with col_toggles:
                c1, c2, c3 = st.columns(3)
                with c1: 
                    st.toggle("IDOR Защита", value=states.get("idor_protection"), key="t_idor", on_change=toggle_feature, args=("idor_protection",))
                with c2: 
                    st.toggle("SQLi Защита", value=states.get("sqli_protection"), key="t_sqli", on_change=toggle_feature, args=("sqli_protection",))
                with c3: 
                    st.toggle("Rate Limit", value=states.get("rate_limit"), key="t_rl", on_change=toggle_feature, args=("rate_limit",))

        st.divider()
        
        # 2. Секция Аналитики
        c_log_head, c_btn = st.columns([8, 2])
        c_log_head.subheader("📊 Аналитика Атак")
        if c_btn.button("🔄 Обновить данные"): st.rerun()

        logs = get_logs()
        if logs:
            df = pd.DataFrame(logs)
            
            # Метрики
            total_attacks = len(df)
            blocked_attacks = len(df[df['result'].str.contains("Blocked")])
            success_attacks = len(df[df['result'].str.contains("Success")])
            
            m1, m2, m3 = st.columns(3)
            m1.metric("Всего событий", total_attacks)
            m2.metric("Заблокировано", blocked_attacks, delta=blocked_attacks, delta_color="normal")
            m3.metric("Пропущено (Уязвимость)", success_attacks, delta=-success_attacks, delta_color="inverse")
            
            # Графики
            if total_attacks > 0:
                chart_col1, chart_col2 = st.columns(2)
                
                with chart_col1:
                    st.caption("Типы атак")
                    # Простой Bar Chart по типам атак
                    attack_counts = df['attack_type'].value_counts()
                    st.bar_chart(attack_counts)
                
                with chart_col2:
                    st.caption("Результативность защиты")
                    # График Blocked vs Success
                    result_counts = df['result'].value_counts()
                    st.bar_chart(result_counts, color="#ffaa00")

            # Таблица логов (свернутая по умолчанию, чтобы не мешать красоте)
            with st.expander("📜 Подробный журнал логов", expanded=True):
                st.dataframe(
                    df[['timestamp', 'ip', 'user', 'attack_type', 'payload', 'result']], 
                    use_container_width=True
                )
        else:
            st.info("Логов пока нет. Проведите атаку!")

    # --- ЛИЧНЫЙ КАБИНЕТ ЮЗЕРА (Без изменений) ---
    else:
        st.title(f"Личный кабинет: {st.session_state.username}")
        col_left, col_right = st.columns([1, 1])
        with col_left:
            st.subheader("📝 Мои Заметки")
            notes = get_my_notes()
            if notes:
                for n in notes:
                    with st.expander(f"📌 {n['title']}"):
                        st.write(n['content'])
                        st.caption(f"ID: {n['id']}")
            else: st.info("Нет заметок.")
            st.divider()
            with st.form("add"):
                t = st.text_input("Заголовок")
                c = st.text_area("Текст")
                if st.form_submit_button("Сохранить"): create_note(t, c)
        with col_right:
            st.subheader("🕵️ Hacker Zone")
            st.warning("Проверка уязвимостей")
            st.write("#### 1. Тест IDOR")
            if st.button("🔥 Украсть заметку Админа"):
                code, data = try_steal_admin_note()
                if code == 200: 
                    st.error("УСПЕХ! ДАННЫЕ УКРАДЕНЫ!")
                    st.json(data)
                else: st.success("ДОСТУП ЗАПРЕЩЕН")
            st.write("#### 2. Тест SQLi")
            if st.button("🔥 SQL-инъекция"):
                code, data = try_sqli_search("' OR '1'='1")
                if code == 200 and len(data)>0: 
                    st.error(f"УСПЕХ! База слита ({len(data)} строк)")
                    st.dataframe(data)
                elif code == 500: st.warning("Ошибка 500 (Server Error)")
                else: st.success("БЕЗОПАСНО")