# --- НЕОБХОДИМЫЕ УСТАНОВКИ ---
#
# 1. Создай venv: python -m venv venv
# 2. Активируй:   source venv/bin/activate (или venv\Scripts\activate)
# 3. Установи:
# pip install "fastapi[all]" uvicorn sqlalchemy passlib[bcrypt] python-jose[cryptography] argon2-cffi
#
# (argon2-cffi может потребовать доп. установки, если не пойдет,
# замени в PWD_CONTEXT "argon2" на "bcrypt" - это тоже безопасно)
#
# 4. Запуск: uvicorn main:app --reload
#
# ---------------------------------

import time
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import List, Optional

# --- FastAPI & Uvicorn ---
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# --- Pydantic (Схемы) ---
from pydantic import BaseModel, ConfigDict

# --- SQLAlchemy (БД) ---
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime, Text, event
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Session, relationship
from sqlalchemy.sql import text # Для демонстрации SQLi

# --- Security (Auth & Hashing) ---
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- Конфигурация ---
DATABASE_URL = "sqlite:///./test.db"
SECRET_KEY = "YOUR_SUPER_SECRET_KEY_CHANGE_ME" # Обязательно смени
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# --- Настройка БД ---
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False} # check_same_thread только для SQLite
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

# --- 1. МОДЕЛИ БАЗЫ ДАННЫХ (SQLAlchemy) ---

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user") # Роли: "user", "admin"
    notes = relationship("Note", back_populates="owner")
    refresh_tokens = relationship("RefreshToken", back_populates="user")

class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    content = Column(Text)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="notes")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String, index=True, unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)
    user = relationship("User", back_populates="refresh_tokens")

class SecurityLog(Base):
    __tablename__ = "security_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.now(timezone.utc))
    ip = Column(String)
    user = Column(String, nullable=True) # Имя пользователя или 'anonymous'
    attack_type = Column(String) # e.g., "IDOR", "SQLi", "Bruteforce"
    payload = Column(Text)
    result = Column(String) # "Success (Vulnerable)", "Blocked (Secure)"

class ConfigFlag(Base):
    __tablename__ = "config_flags"
    id = Column(Integer, primary_key=True)
    feature = Column(String, unique=True, index=True) # "idor_protection", "sqli_protection", "rate_limit"
    enabled = Column(Boolean, default=False)


# --- 2. СХЕМЫ ДАННЫХ (Pydantic) ---

# --- Users & Auth ---
class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    role: str = "user"

class UserInDB(UserBase):
    id: int
    role: str
    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

# --- Notes ---
class NoteBase(BaseModel):
    title: str
    content: Optional[str] = None

class NoteCreate(NoteBase):
    pass

class NoteSchema(NoteBase):
    id: int
    owner_id: int
    model_config = ConfigDict(from_attributes=True)

# --- Admin ---
class SecurityLogSchema(BaseModel):
    id: int
    timestamp: datetime
    ip: str
    user: Optional[str]
    attack_type: str
    payload: str
    result: str
    model_config = ConfigDict(from_attributes=True)

class ConfigFlagSchema(BaseModel):
    feature: str
    enabled: bool
    model_config = ConfigDict(from_attributes=True)


# --- 3. ИНИЦИАЛИЗАЦИЯ ПРИЛОЖЕНИЯ ---
app = FastAPI(title="Vulnerable REST API Demo")

# --- 4. УТИЛИТЫ БЕЗОПАСНОСТИ И AUTH ---

# --- Hashing ---
# --- Hashing ---
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto") # (Предпочтительно, но требует argon2-cffi)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# --- JWT Creation ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def create_refresh_token(data: dict, db: Session, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({"exp": expire})
    # JTI (JWT ID) для уникальности токена
    jti = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM) 
    
    user = db.query(User).filter(User.username == data.get("sub")).first()
    
    db_token = RefreshToken(
        user_id=user.id,
        token=jti,
        expires_at=expire
    )
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    return jti

# --- Auth Dependencies ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception
        
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    # (Здесь можно добавить проверку на user.disabled, если нужно)
    return current_user

# --- RBAC (Role-Based Access Control) Dependency ---
def require_role(role: str):
    async def role_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.role != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted for your role"
            )
        return current_user
    return role_checker

# --- 5. УТИЛИТЫ ЛОГГИРОВАНИЯ И КОНФИГУРАЦИИ ---

# --- Security Log Helper ---
def log_security_event(db: Session, ip: str, attack_type: str, payload: str, user: Optional[str] = 'anonymous', result: str = "Blocked (Secure)"):
    """
    Логгирует событие безопасности.
    result: "Success (Vulnerable)" или "Blocked (Secure)"
    """
    log_entry = SecurityLog(
        ip=ip,
        user=user,
        attack_type=attack_type,
        payload=payload,
        result=result
    )
    db.add(log_entry)
    db.commit()

# --- Config Flag Helper ---
def get_config_flag(feature: str, db: Session) -> bool:
    """Проверяет, включена ли защита"""
    flag = db.query(ConfigFlag).filter(ConfigFlag.feature == feature).first()
    return flag.enabled if flag else False

# --- Rate Limiter (Brute-force) ---
# (Простой In-Memory лимитер для демо. В проде нужен Redis)
RATE_LIMIT_DB = defaultdict(lambda: {"count": 0, "start_time": time.time()})
MAX_REQUESTS = 5
WINDOW_SECONDS = 60

def ip_rate_limit(request: Request, db: Session = Depends(get_db)):
    # 1. Проверяем, включен ли Rate Limiter
    if not get_config_flag("rate_limit", db):
        return True # Защита выключена, пропускаем
        
    ip = request.client.host
    now = time.time()
    
    data = RATE_LIMIT_DB[ip]
    
    # 2. Сброс окна
    if now - data["start_time"] > WINDOW_SECONDS:
        data["start_time"] = now
        data["count"] = 1
    else:
        data["count"] += 1

    # 3. Проверка лимита
    if data["count"] > MAX_REQUESTS:
        log_security_event(
            db=db,
            ip=ip,
            attack_type="Bruteforce",
            payload=f"Attempt {data['count']} in {WINDOW_SECONDS}s",
            result="Blocked (Secure)"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please wait."
        )
    return True

# --- 6. ЗАПУСК И MIDDLEWARE ---

# --- Создание таблиц при старте ---
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    
    # Инициализация флагов защиты (по умолчанию ВЫКЛЮЧЕНЫ)
    db = SessionLocal()
    flags = ["idor_protection", "sqli_protection", "rate_limit"]
    for flag_name in flags:
        flag = db.query(ConfigFlag).filter(ConfigFlag.feature == flag_name).first()
        if not flag:
            db.add(ConfigFlag(feature=flag_name, enabled=False))
    
    # (Опционально) Создание админа при первом запуске
    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        admin_user = User(
            username="admin",
            hashed_password=get_password_hash("admin123"), # СМЕНИ ЭТОТ ПАРОЛЬ
            role="admin"
        )
        db.add(admin_user)
        
    # (Опционально) Создание тестовых юзеров
    alice = db.query(User).filter(User.username == "alice").first()
    if not alice:
        db.add(User(username="alice", hashed_password=get_password_hash("alice123"), role="user"))
        
    bob = db.query(User).filter(User.username == "bob").first()
    if not bob:
        db.add(User(username="bob", hashed_password=get_password_hash("bob123"), role="user"))

    db.commit()
    
    # (Опционально) Добавление тестовых данных
    if db.query(Note).count() == 0:
        alice = db.query(User).filter(User.username == "alice").first()
        bob = db.query(User).filter(User.username == "bob").first()
        
        db.add(Note(title="Alice's Secret Note", content="My password is alice123", owner_id=alice.id))
        db.add(Note(title="Bob's Public Note", content="Shopping list", owner_id=bob.id))
        db.add(Note(title="Bob's Secret Note", content="My password is bob123", owner_id=bob.id))
        db.commit()
        
    db.close()

# --- Security Headers Middleware ---
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

# --- 7. ОСНОВНЫЕ ЭНДПОИНТЫ (API) ---

@app.post("/register", response_model=UserInDB)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """Регистрация нового пользователя"""
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username, 
        hashed_password=hashed_password, 
        role=user.role if user.role in ["user", "admin"] else "user" # Убедимся, что роль валидна
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=Token)
async def login_for_access_token(
    request: Request, # Для IP
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
    rate_limited: bool = Depends(ip_rate_limit) # 👈 Защита от Brute-force
):
    """
    Получение Access и Refresh токенов.
    Защищено Rate Limiter'ом.
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        # Логгируем неудачную попытку входа
        log_security_event(
            db=db,
            ip=request.client.host,
            attack_type="Bruteforce",
            payload=f"Failed login attempt for user: {form_data.username}",
            result="Blocked (Secure)" # Технически это не атака, а неудача, но для демо сойдет
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Создаем access token
    access_token_data = {"sub": user.username, "role": user.role}
    access_token = create_access_token(
        data=access_token_data, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    # Создаем и сохраняем refresh token
    refresh_token = await create_refresh_token(
        data={"sub": user.username}, 
        db=db,
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post("/token/refresh", response_model=Token)
async def refresh_access_token(
    request: Request,
    refresh_token: str = Depends(oauth2_scheme), # Получаем refresh токен как Bearer
    db: Session = Depends(get_db)
):
    """
    Обновление Access Token с помощью Refresh Token.
    Refresh Token при этом аннулируется (one-time use).
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # 1. Найти токен в БД
    db_token = db.query(RefreshToken).filter(RefreshToken.token == refresh_token).first()
    
    if not db_token or db_token.revoked or db_token.expires_at < datetime.now(timezone.utc):
        # Если токен не найден, истек или уже был использован -> 401
        raise credentials_exception
        
    # 2. Декодировать токен (на всякий случай, хотя мы доверяем БД)
    try:
        payload = jwt.decode(db_token.token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise credentials_exception
        
    # 3. Аннулировать старый refresh-токен (ОБЯЗАТЕЛЬНО!)
    db_token.revoked = True
    db.commit()
    
    # 4. Выдать новую пару токенов
    new_access_token_data = {"sub": user.username, "role": user.role}
    new_access_token = create_access_token(
        data=new_access_token_data, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    new_refresh_token = await create_refresh_token(
        data={"sub": user.username}, 
        db=db,
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    
    return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}


# --- 8. ДЕМОНСТРАЦИОННЫЕ ЭНДПОИНТЫ (Уязвимости) ---

@app.post("/notes", response_model=NoteSchema)
def create_note(
    note: NoteCreate, 
    current_user: User = Depends(get_current_active_user), 
    db: Session = Depends(get_db)
):
    """Создание новой заметки (для тестов)"""
    db_note = Note(**note.model_dump(), owner_id=current_user.id)
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    return db_note

@app.get("/notes", response_model=List[NoteSchema])
def get_my_notes(
    current_user: User = Depends(get_current_active_user), 
    db: Session = Depends(get_db)
):
    """Получение списка МОИХ заметок (безопасно)"""
    return db.query(Note).filter(Note.owner_id == current_user.id).all()

# ---
# --- 🔴 IDOR (BOLA) ЭНДПОИНТ 🔴 ---
# ---
@app.get("/notes/{note_id}", response_model=NoteSchema)
def get_note_by_id(
    note_id: int, 
    request: Request, # Для IP
    current_user: User = Depends(get_current_active_user), 
    db: Session = Depends(get_db)
):
    """
    Получение заметки по ID.
    Поведение меняется в зависимости от флага 'idor_protection'.
    """
    
    # 1. Проверяем флаг защиты
    protection_enabled = get_config_flag("idor_protection", db)
    
    if protection_enabled:
        # --- ✅ БЕЗОПАСНЫЙ РЕЖИМ (ON) ---
        # Ищем заметку И проверяем, что владелец = текущий юзер
        note = db.query(Note).filter(
            Note.id == note_id, 
            Note.owner_id == current_user.id
        ).first()
        
        if not note:
            # Логгируем ПОПЫТКУ атаки
            log_security_event(
                db=db,
                ip=request.client.host,
                user=current_user.username,
                attack_type="IDOR",
                payload=f"Attempt to access note_id={note_id}",
                result="Blocked (Secure)"
            )
            raise HTTPException(status_code=404, detail="Note not found or access denied")
            
    else:
        # --- ❌ УЯЗВИМЫЙ РЕЖИМ (OFF) ---
        # Просто ищем заметку по ID, не проверяя владельца
        note = db.query(Note).filter(Note.id == note_id).first()
        
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
            
        # Если мы здесь, значит заметка найдена.
        # Если она чужая - это УСПЕШНАЯ АТАКА.
        if note.owner_id != current_user.id:
            log_security_event(
                db=db,
                ip=request.client.host,
                user=current_user.username,
                attack_type="IDOR",
                payload=f"Successful access to note_id={note_id} (owner={note.owner_id})",
                result="Success (Vulnerable)"
            )
            
    return note

# ---
# --- 🔴 SQL Injection (SQLi) ЭНДПОИНТ 🔴 ---
# ---
@app.get("/search") # response_model=List[NoteSchema] - не можем использовать, т.к. raw sql возвращает не объекты
def search_notes(
    query: str, 
    request: Request, # Для IP
    current_user: User = Depends(get_current_active_user), 
    db: Session = Depends(get_db)
):
    """
    Поиск заметок по названию.
    Поведение меняется в зависимости от флага 'sqli_protection'.
    """
    
    # 1. Проверяем флаг защиты
    protection_enabled = get_config_flag("sqli_protection", db)
    
    if protection_enabled:
        # --- ✅ БЕЗОПАСНЫЙ РЕЖИМ (ON) ---
        # Используем ORM-параметризованный запрос.
        # (И ВСЕГДА фильтруем по owner_id, чтобы не было IDOR в поиске)
        search_query = f"%{query}%"
        results = db.query(Note).filter(
            Note.owner_id == current_user.id,
            Note.title.ilike(search_query)
        ).all()
        
        # Логгируем попытку атаки, если она была (например, ' OR '1'='1)
        if "'" in query or "OR" in query.upper():
             log_security_event(
                db=db,
                ip=request.client.host,
                user=current_user.username,
                attack_type="SQLi",
                payload=f"Blocked SQLi attempt: {query}",
                result="Blocked (Secure)"
            )
        
        return results
            
    else:
        # --- ❌ УЯЗВИМЫЙ РЕЖИМ (OFF) ---
        # ОЧЕНЬ ПЛОХОЙ КОД: Прямая вставка строки в SQL
        
        # Мы используем text() для исполнения raw SQL, но проблема 500 ошибки
        # часто возникает из-за того, как SQLAlchemy обрабатывает кавычки.
        # Упростим запрос для надежности демо:
        
        raw_sql = "SELECT id, title, content, owner_id FROM notes WHERE title LIKE '%" + query + "%'"
        
        try:
            # Выполняем небезопасный запрос
            # connection.execute() возвращает курсор, из него берем данные
            results = db.execute(text(raw_sql)).fetchall()
            
            # Преобразуем результат в список словарей (чтобы Pydantic не ругался)
            notes_list = []
            for row in results:
                # row - это кортеж или объект Row, зависисит от версии
                notes_list.append({
                    "id": row.id,
                    "title": row.title,
                    "content": row.content,
                    "owner_id": row.owner_id
                })

            # Логгируем УСПЕШНУЮ атаку
            if "'" in query or "OR" in query.upper():
                 log_security_event(
                    db=db,
                    ip=request.client.host,
                    user=current_user.username,
                    attack_type="SQLi",
                    payload=f"Vulnerable SQL executed: {raw_sql}",
                    result="Success (Vulnerable)"
                )
                 
            return notes_list
            
        except Exception as e:
            # Если SQL совсем кривой, вернем ошибку, но понятную
            print(f"SQL Error: {e}") # Для отладки в консоль
            log_security_event(
                db=db,
                ip=request.client.host,
                user=current_user.username,
                attack_type="SQLi",
                payload=f"Failed SQL execution: {raw_sql}",
                result="Blocked (Error 500)"
            )
            # Возвращаем пустой список вместо краша 500, чтобы скрипт не падал
            return []


# --- 9. АДМИН-ЭНДПОИНТЫ ---

# Зависимость "Только Админ"
AdminOnly = Depends(require_role("admin"))

@app.get("/admin/logs", response_model=List[SecurityLogSchema])
def get_security_logs(
    current_admin: User = AdminOnly, 
    db: Session = Depends(get_db)
):
    """[Admin] Получить все логи безопасности"""
    return db.query(SecurityLog).order_by(SecurityLog.timestamp.desc()).all()

@app.get("/admin/config", response_model=List[ConfigFlagSchema])
def get_all_config_flags(
    current_admin: User = AdminOnly, 
    db: Session = Depends(get_db)
):
    """[Admin] Получить текущее состояние всех флагов защиты"""
    return db.query(ConfigFlag).all()

@app.post("/admin/toggle/{feature}", response_model=ConfigFlagSchema)
def toggle_feature_flag(
    feature: str,
    current_admin: User = AdminOnly, 
    db: Session = Depends(get_db)
):
    """[Admin] Переключить флаг защиты (ON/OFF)"""
    flag = db.query(ConfigFlag).filter(ConfigFlag.feature == feature).first()
    
    if not flag:
        raise HTTPException(status_code=404, detail=f"Feature '{feature}' not found")
        
    flag.enabled = not flag.enabled
    db.commit()
    db.refresh(flag)
    
    # Логгируем действие админа
    log_security_event(
        db=db,
        ip="localhost", # Админское действие
        user=current_admin.username,
        attack_type="Admin Action",
        payload=f"Toggled '{feature}' to {flag.enabled}",
        result="Info"
    )
    
    return flag