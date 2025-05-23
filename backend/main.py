from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
import models
from database import get_db
from auth import (
    create_token, authenticate_user,
    register_user, get_current_user,
    require_role
)
from services import load_policy, save_event, find_unassigned, log_unauthorized_access
import init_db
from fastapi.responses import FileResponse
import os
import sys
from utils import load_and_validate_policy, call_cloud_service_with_fallback, filter_and_translate_policy

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db.init()

# Проверка политики безопасности при старте приложения
try:
    security_policy, policy_checksum = load_and_validate_policy()
    print(f"Политика безопасности загружена. Контрольная сумма: {policy_checksum}")
except Exception as e:
    print(f"Ошибка загрузки политики безопасности: {e}")
    sys.exit(1)  # Завершаем приложение при ошибке

# Проверка связи с облаком с fallback
call_cloud_service_with_fallback()

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(data.username, data.password, db)
    return {"token": create_token(user)}

@app.post("/register")
def register(data: LoginRequest, db: Session = Depends(get_db)):
    user = register_user(data.username, data.password, db)
    return {"msg": f"User {user.username} registered"}

@app.get("/policy")
def get_policy(user = Depends(get_current_user)):
    policy = load_policy()  # Загружаем всю политику из файла
    filtered_policy = filter_and_translate_policy(policy, user.role)
    return filtered_policy

@app.get("/responsibility_gap")
def gap(user = Depends(get_current_user)):
    # Если роль не admin — логируем попытку несанкционированного доступа и возвращаем ошибку
    if user.role != "admin":
        log_unauthorized_access(user.username, "/responsibility_gap")
        raise HTTPException(status_code=403, detail="Access denied")
    return {"unassigned": find_unassigned()}

@app.post("/log_event")
async def log_event(request: Request, user = Depends(require_role("admin"))):
    data = await request.json()
    save_event(data.get("event", "unknown"))
    return {"status": "logged"}

@app.get("/make_admin/{username}")
def make_admin(username: str, user = Depends(require_role("admin")), db: Session = Depends(get_db)):
    u = db.query(models.User).filter(models.User.username == username).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u.role = "admin"
    db.commit()
    return {"msg": f"User {username} promoted to admin"}

@app.get("/")
@app.get("/frontend/index.html")
def frontend_page():
    path = os.path.join(os.getcwd(), "frontend", "index.html")
    if os.path.exists(path):
        return FileResponse(path)
    else:
        return {"error": "index.html not found"}
