# 🛡️ API Security Demo Stand

Проект для демонстрации уязвимостей REST API и методов их защиты.
Проект реализует симуляцию атак (IDOR, SQL Injection, Brute-force) и позволяет в реальном времени включать/выключать механизмы защиты через панель администратора.

## 🏗️ Архитектура

* **Backend:** FastAPI (Python) — реализация API, JWT Auth, RBAC.
* **Database:** SQLite + SQLAlchemy (ORM).
* **Frontend(Admin UI).:** Streamlit — панель управления защитой и мониторинг логов.
* **Security:** Argon2 (hashing), JWT (Access/Refresh), Rate Limiting.
* **Monitoring:**@BotFather Telegram bot - REST_Alert_Bot 
