# ---------------------------------
# main.py - Полный код с Telegram оповещениями
# ---------------------------------

import time
import logging
import os
import requests # <--- Нужно для Telegram
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import List, Optional

# Загрузка переменных окружения
load_dotenv()

# --- FastAPI & Uvicorn ---
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# --- Pydantic (Схемы) ---
from pydantic import BaseModel, ConfigDict

# --- SQLAlchemy (БД) ---
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime, Text
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Session, relationship
from sqlalchemy.sql import text

# --- Security (Auth & Hashing) ---
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- Конфигурация ---
DATABASE_URL = "sqlite:///./test.db"

# Секреты (читаем из .env)
SECRET_KEY = os.getenv("SECRET_KEY", "unsafe-default-key-for-dev") 
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN")
TG_CHAT_ID = os.getenv("TG_CHAT_ID")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# --- Настройка БД ---
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False} 
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
    role = Column(String, default="user") 
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
    user = Column(String, nullable=True) 
    attack_type = Column(String) 
    payload = Column(Text)
    result = Column(String) 

class ConfigFlag(Base):
    __tablename__ = "config_flags"
    id = Column(Integer, primary_key=True)
    feature = Column(String, unique=True, index=True) 
    enabled = Column(Boolean, default=False)


# --- 2. СХЕМЫ ДАННЫХ (Pydantic) ---

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

class NoteBase(BaseModel):
    title: str
    content: Optional[str] = None

class NoteCreate(NoteBase):
    pass

class NoteSchema(NoteBase):
    id: int
    owner_id: int
    model_config = ConfigDict(from_attributes=True)

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
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

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
    return current_user

def require_role(role: str):
    async def role_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.role != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted for your role"
            )
        return current_user
    return role_checker

# --- 5. УТИЛИТЫ ЛОГГИРОВАНИЯ И TELEGRAM ---

# --- Telegram Alert ---
def send_security_alert(log: SecurityLog):
    """Отправляет уведомление в Telegram о критическом событии."""
    
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return 

    # Формируем иконки
    if "Success (Vulnerable)" in log.result:
        icon = "🚨"
        action = "🔥 АТАКА УСПЕШНА (VULNERABLE)"
    elif "Blocked" in log.result:
        icon = "🛡️"
        action = "✅ АТАКА ОТРАЖЕНА (SECURE)"
    else:
        icon = "⚙️"
        action = "⚙️ ИНФО"
        
    message_text = f"""
{icon} *СОБЫТИЕ БЕЗОПАСНОСТИ API* {icon}
-------------------------------------
*Тип:* {log.attack_type}
*Результат:* {action}
*Пользователь:* {log.user or 'Аноним'}
*IP:* {log.ip}
*Время (UTC):* {log.timestamp.strftime('%H:%M:%S %d.%m')}
*Payload:* `{log.payload[:100]}...`
-------------------------------------
"""
    # Отправка через API Telegram
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TG_CHAT_ID,
        "text": message_text,
        "parse_mode": "Markdown"
    }

    try:
        requests.post(url, data=payload, timeout=5)
    except Exception as e:
        print(f"TELEGRAM ERROR: Failed to send alert. {e}")

# --- Security Log Helper ---
def log_security_event(db: Session, ip: str, attack_type: str, payload: str, user: Optional[str] = 'anonymous', result: str = "Blocked (Secure)"):
    """
    Логгирует событие безопасности и отправляет оповещение в ТГ.
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
    db.refresh(log_entry) # Получаем ID и timestamp после коммита
    
    # Отправка в Telegram (не отправляем обычные админские действия и ошибки 500, чтобы не спамить)
    if result not in ["Info", "Blocked (Error 500)"]:
        send_security_alert(log_entry)

# --- Config Flag Helper ---
def get_config_flag(feature: str, db: Session) -> bool:
    flag = db.query(ConfigFlag).filter(ConfigFlag.feature == feature).first()
    return flag.enabled if flag else False

# --- Rate Limiter ---
RATE_LIMIT_DB = defaultdict(lambda: {"count": 0, "start_time": time.time()})
MAX_REQUESTS = 5
WINDOW_SECONDS = 60

def ip_rate_limit(request: Request, db: Session = Depends(get_db)):
    if not get_config_flag("rate_limit", db):
        return True 
        
    ip = request.client.host
    now = time.time()
    
    data = RATE_LIMIT_DB[ip]
    
    if now - data["start_time"] > WINDOW_SECONDS:
        data["start_time"] = now
        data["count"] = 1
    else:
        data["count"] += 1

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

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    flags = ["idor_protection", "sqli_protection", "rate_limit"]
    for flag_name in flags:
        flag = db.query(ConfigFlag).filter(ConfigFlag.feature == flag_name).first()
        if not flag:
            db.add(ConfigFlag(feature=flag_name, enabled=False))
    
    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        admin_user = User(
            username="admin",
            hashed_password=get_password_hash("admin123"),
            role="admin"
        )
        db.add(admin_user)
        
    alice = db.query(User).filter(User.username == "alice").first()
    if not alice:
        db.add(User(username="alice", hashed_password=get_password_hash("alice123"), role="user"))
        
    bob = db.query(User).filter(User.username == "bob").first()
    if not bob:
        db.add(User(username="bob", hashed_password=get_password_hash("bob123"), role="user"))

    db.commit()
    
    if db.query(Note).count() == 0:
        alice = db.query(User).filter(User.username == "alice").first()
        bob = db.query(User).filter(User.username == "bob").first()
        
        db.add(Note(title="Alice's Secret Note", content="My password is alice123", owner_id=alice.id))
        db.add(Note(title="Bob's Public Note", content="Shopping list", owner_id=bob.id))
        db.add(Note(title="Bob's Secret Note", content="My password is bob123", owner_id=bob.id))
        db.commit()
        
    db.close()

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
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username, 
        hashed_password=hashed_password, 
        role=user.role if user.role in ["user", "admin"] else "user"
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=Token)
async def login_for_access_token(
    request: Request,
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
    rate_limited: bool = Depends(ip_rate_limit)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        log_security_event(
            db=db,
            ip=request.client.host,
            attack_type="Bruteforce",
            payload=f"Failed login attempt for user: {form_data.username}",
            result="Blocked (Secure)"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_data = {"sub": user.username, "role": user.role}
    access_token = create_access_token(
        data=access_token_data, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    refresh_token = await create_refresh_token(
        data={"sub": user.username}, 
        db=db,
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post("/token/refresh", response_model=Token)
async def refresh_access_token(
    request: Request,
    refresh_token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    db_token = db.query(RefreshToken).filter(RefreshToken.token == refresh_token).first()
    
    if not db_token or db_token.revoked or db_token.expires_at < datetime.now(timezone.utc):
        raise credentials_exception
        
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
        
    db_token.revoked = True
    db.commit()
    
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
    return db.query(Note).filter(Note.owner_id == current_user.id).all()

# --- 🔴 IDOR (BOLA) ---
@app.get("/notes/{note_id}", response_model=NoteSchema)
def get_note_by_id(
    note_id: int, 
    request: Request, 
    current_user: User = Depends(get_current_active_user), 
    db: Session = Depends(get_db)
):
    protection_enabled = get_config_flag("idor_protection", db)
    
    if protection_enabled:
        # ✅ БЕЗОПАСНО
        note = db.query(Note).filter(
            Note.id == note_id, 
            Note.owner_id == current_user.id
        ).first()
        
        if not note:
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
        # ❌ УЯЗВИМО
        note = db.query(Note).filter(Note.id == note_id).first()
        
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
            
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

# --- 🔴 SQL Injection (SQLi) ---
@app.get("/search") 
def search_notes(
    query: str, 
    request: Request, 
    current_user: User = Depends(get_current_active_user), 
    db: Session = Depends(get_db)
):
    protection_enabled = get_config_flag("sqli_protection", db)
    
    if protection_enabled:
        # ✅ БЕЗОПАСНО
        search_query = f"%{query}%"
        results = db.query(Note).filter(
            Note.owner_id == current_user.id,
            Note.title.ilike(search_query)
        ).all()
        
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
        # ❌ УЯЗВИМО (Специально)
        raw_sql = "SELECT id, title, content, owner_id FROM notes WHERE title LIKE '%" + query + "%'"
        
        try:
            results = db.execute(text(raw_sql)).fetchall()
            
            notes_list = []
            for row in results:
                notes_list.append({
                    "id": row.id,
                    "title": row.title,
                    "content": row.content,
                    "owner_id": row.owner_id
                })

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
            print(f"SQL Error: {e}") 
            log_security_event(
                db=db,
                ip=request.client.host,
                user=current_user.username,
                attack_type="SQLi",
                payload=f"Failed SQL execution: {raw_sql}",
                result="Blocked (Error 500)"
            )
            return []


# --- 9. АДМИН-ЭНДПОИНТЫ ---

AdminOnly = Depends(require_role("admin"))

@app.get("/admin/logs", response_model=List[SecurityLogSchema])
def get_security_logs(
    current_admin: User = AdminOnly, 
    db: Session = Depends(get_db)
):
    return db.query(SecurityLog).order_by(SecurityLog.timestamp.desc()).all()

@app.get("/admin/config", response_model=List[ConfigFlagSchema])
def get_all_config_flags(
    current_admin: User = AdminOnly, 
    db: Session = Depends(get_db)
):
    return db.query(ConfigFlag).all()

@app.post("/admin/toggle/{feature}", response_model=ConfigFlagSchema)
def toggle_feature_flag(
    feature: str,
    current_admin: User = AdminOnly, 
    db: Session = Depends(get_db)
):
    flag = db.query(ConfigFlag).filter(ConfigFlag.feature == feature).first()
    
    if not flag:
        raise HTTPException(status_code=404, detail=f"Feature '{feature}' not found")
        
    flag.enabled = not flag.enabled
    db.commit()
    db.refresh(flag)
    
    log_security_event(
        db=db,
        ip="localhost", 
        user=current_admin.username,
        attack_type="Admin Action",
        payload=f"Toggled '{feature}' to {flag.enabled}",
        result="Info"
    )
    
    return flag