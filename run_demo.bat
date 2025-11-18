@echo off
title API Security Launcher
echo ==========================================
echo    STARTING SECURITY DEMO STAND
echo ==========================================

:: 1. Запускаем API (FastAPI) в отдельном окне
echo Starting Backend...
start "API Server (Main.py)" cmd /k ".\venv\Scripts\activate && uvicorn main:app --reload"

:: Ждем 3 секунды, пока сервер прогрузится
timeout /t 3 /nobreak >nul

:: 2. Запускаем Админку (Streamlit) в отдельном окне
echo Starting Dashboard...
start "Admin Dashboard" cmd /k ".\venv\Scripts\activate && streamlit run dashboard.py"

:: 3. Оставляем текущее окно для запуска атак
echo.
echo ==========================================
echo    SYSTEM READY!
echo ==========================================
echo.
echo To run the attack simulation, type:
echo python attack_demo.py
echo.

:: Активируем venv в этом окне, чтобы ты мог сразу писать команды
cmd /k ".\venv\Scripts\activate"