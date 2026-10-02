import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional
from pydantic import BaseModel
import io
import os
import uvicorn

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from database import DB_FILE, init_db, log_activity
from models import AgentData, AgentEmailData
from auth import (
    security, 
    get_password_hash, 
    verify_password, 
    create_access_token, 
    verify_access_token, 
    ACCESS_TOKEN_EXPIRE_MINUTES
)

# إعداد حماية معدل الطلبات (Rate Limiting) لمنع هجمات التخمين Brute Force
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# حالة الصيانة العامة للسيرفر
system_maintenance_mode = False

# المفتاح السري الخاص بالأدمن (تم التعديل إلى مفتاحك الشخصي)
ADMIN_SECRET_KEY = "jawad_secret_2026"

class HackAttemptData(BaseModel):
    difficulty: Optional[str] = "easy"
    time_taken: Optional[float] = 0.0
    success: Optional[bool] = True
    device_info: Optional[str] = "Godot Client"

@app.on_event("startup")
def startup_event():
    init_db()

@app.post("/register")
@limiter.limit("5/minute")
def register_agent(request: Request, agent: AgentData):
    email = agent.email.strip()
    password = agent.password.strip()
    
    if not email.endswith("@gmail.com"):
        return {"status": "error", "message": "Only Gmail accounts are allowed!"}
    
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            return {"status": "error", "message": "Agent already exists!"}
        
        hashed_password = get_password_hash(password)
        cursor.execute("INSERT INTO users (email, password, status) VALUES (?, ?, 'active')", (email, hashed_password))
        conn.commit()
    
    log_activity(f"New agent registered: {email}", f"تم تسجيل عميل جديد: {email}", email=email, action_type="REGISTER")
    return {"status": "success", "message": "Agent registered successfully!"}

@app.post("/login")
@limiter.limit("10/minute")
def login_agent(request: Request, agent: AgentData):
    if system_maintenance_mode:
        return {"status": "error", "message": "Server is under maintenance. Access restricted."}

    email = agent.email.strip()
    password = agent.password.strip()
    
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password, status FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        
        if not user or not verify_password(password, user[0]):
            return {"status": "error", "message": "Invalid credentials!"}
        
        if user[1] == 'banned':
            return {"status": "error", "message": "Access Denied: Agent is banned!"}
        
        current_time = datetime.now(timezone.utc).isoformat()
        cursor.execute("SELECT score FROM player_scores WHERE email = ?", (email,))
        row = cursor.fetchone()
        if row is None:
            cursor.execute("INSERT INTO player_scores (email, score, last_win) VALUES (?, 0, ?)", (email, current_time))
        else:
            cursor.execute("UPDATE player_scores SET last_win = ? WHERE email = ?", (current_time, email))
            
        conn.commit()
    
    access_token = create_access_token(data={"sub": email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {
        "status": "success", 
        "message": "Login successful!", 
        "token": access_token
    }

@app.post("/api/pwn-target")
def pwn_target(
    attempt: Optional[HackAttemptData] = None, 
    request: Request = None,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    if system_maintenance_mode:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Server is under maintenance.")

    email = verify_access_token(credentials.credentials)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access Denied.")
    
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM users WHERE email = ?", (email,))
        user_status = cursor.fetchone()
        if user_status and user_status[0] == 'banned':
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is banned.")

        if attempt is None:
            attempt = HackAttemptData()

        diff = attempt.difficulty.lower() if attempt.difficulty else "easy"
        base_points = 100
        if diff == "medium":
            base_points = 250
        elif diff == "hard":
            base_points = 500

        earned_points = 0
        if attempt.success:
            speed_bonus = max(0, 50 - int(attempt.time_taken))
            earned_points = base_points + speed_bonus

        current_time = datetime.now(timezone.utc).isoformat()
        cursor.execute("SELECT score FROM player_scores WHERE email = ?", (email,))
        row = cursor.fetchone()
        
        if row is None:
            new_score = earned_points
            cursor.execute("INSERT INTO player_scores (email, score, last_win) VALUES (?, ?, ?)", 
                           (email, new_score, current_time if attempt.success else None))
        else:
            new_score = row[0] + earned_points
            if attempt.success:
                cursor.execute("UPDATE player_scores SET score = ?, last_win = ? WHERE email = ?", (new_score, current_time, email))
            else:
                cursor.execute("UPDATE player_scores SET score = ? WHERE email = ?", (new_score, email))
            
        conn.commit()

    client_ip = request.client.host if request and request.client else "Unknown IP"
    device_str = f"{attempt.device_info} [IP: {client_ip}]"
    status_str = "SUCCESS" if attempt.success else "FAILED"
    diff_upper = diff.upper() if isinstance(diff, str) else "EASY"

    if attempt.success:
        msg_en = f"Agent {email} BREACH SUCCESS [{diff_upper}] (+{earned_points} pts) - IP: {client_ip}"
        msg_ar = f"العميل {email} نجح بالإختراق [{diff}] (+{earned_points} نقطة) - IP: {client_ip}"
    else:
        msg_en = f"Agent {email} BREACH FAILED [{diff_upper}] - Device: {device_str}"
        msg_ar = f"العميل {email} فشل بالإختراق [{diff}] - الجهاز: {device_str}"

    log_activity(
        msg_en=msg_en, 
        msg_ar=msg_ar, 
        email=email, 
        action_type="BREACH_ATTEMPT", 
        difficulty=diff, 
        points=earned_points, 
        status_val=status_str, 
        device_info=device_str
    )

    return {
        "status": "success" if attempt.success else "failed", 
        "score": new_score,
        "earned_points": earned_points,
        "message": "Access Granted" if attempt.success else "Breach Blocked"
    }

@app.get("/api/profile")
def get_agent_profile(credentials: HTTPAuthorizationCredentials = Depends(security)):
    email = verify_access_token(credentials.credentials)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access Denied.")
    
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM users WHERE email = ?", (email,))
        user_row = cursor.fetchone()
        if not user_row or user_row[0] == 'banned':
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is banned or not found.")
            
        cursor.execute("SELECT score, last_win FROM player_scores WHERE email = ?", (email,))
        score_row = cursor.fetchone()
    
    score = score_row[0] if score_row else 0
    last_win = score_row[1] if score_row and score_row[1] else "NEVER_PWNED"
    
    return {
        "status": "success",
        "email": email,
        "score": score,
        "last_win": last_win,
        "maintenance": system_maintenance_mode
    }

@app.post("/api/admin/reset-score")
def reset_agent_score(data: AgentEmailData):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE player_scores SET score = 0 WHERE email = ?", (data.email,))
        conn.commit()
    log_activity(f"Score reset for agent {data.email}", f"تم تصفير النقاط للعميل {data.email}", email=data.email, action_type="RESET_SCORE")
    return {"status": "success"}

@app.post("/api/admin/toggle-ban")
def toggle_ban_agent(data: AgentEmailData):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM users WHERE email = ?", (data.email,))
        row = cursor.fetchone()
        if row:
            new_status = 'banned' if row[0] == 'active' else 'active'
            cursor.execute("UPDATE users SET status = ? WHERE email = ?", (new_status, data.email))
            conn.commit()
            action_name = "banned" if new_status == 'banned' else "unbanned"
            log_activity(f"Agent {data.email} was {action_name}", f"تم تعديل حالة العميل {data.email} إلى {action_name}", email=data.email, action_type="TOGGLE_BAN")
            return {"status": "success", "new_status": new_status}
    return {"status": "error"}

@app.post("/api/admin/toggle-maintenance")
def toggle_maintenance():
    global system_maintenance_mode
    system_maintenance_mode = not system_maintenance_mode
    status_text = "ENABLED" if system_maintenance_mode else "DISABLED"
    log_activity(f"Maintenance mode {status_text}", f"تم تغيير وضع الصيانة إلى: {status_text}", action_type="MAINTENANCE")
    return {"status": "success", "maintenance": system_maintenance_mode}

@app.get("/api/admin/export-logs")
def export_logs_csv():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, action_type, message_en, timestamp FROM activity_logs ORDER BY id DESC")
        rows = cursor.fetchall()

    output = io.StringIO()
    output.write("ID,Email,Action Type,Message,Timestamp\n")
    for row in rows:
        output.write(f"{row[0]},{row[1] or 'SYSTEM'},{row[2] or 'GENERAL'},\"{row[3]}\",{row[4]}\n")
    
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cyber_activity_logs.csv"}
    )

@app.get("/api/admin/stats")
def get_admin_stats():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT users.email, users.status, COALESCE(player_scores.score, 0), player_scores.last_win 
            FROM users 
            LEFT JOIN player_scores ON users.email = player_scores.email
            ORDER BY COALESCE(player_scores.score, 0) DESC
        """)
        rows = cursor.fetchall()
        
        cursor.execute("SELECT message_en, message_ar, timestamp FROM activity_logs ORDER BY id DESC LIMIT 15")
        log_rows = cursor.fetchall()
    
    agents_data = []
    total_score = 0
    banned_count = 0
    now_utc = datetime.now(timezone.utc)
    
    for index, row in enumerate(rows):
        email = row[0]
        status_val = row[1]
        score = row[2]
        last_win = row[3]
        
        total_score += score
        if status_val == 'banned':
            banned_count += 1
            
        is_online = False
        if last_win and last_win != "NEVER_PWNED":
            try:
                last_time = datetime.fromisoformat(last_win)
                if (now_utc - last_time).total_seconds() < 180:
                    is_online = True
            except Exception:
                pass
            
        agents_data.append({
            "rank": index + 1,
            "email": email,
            "status": status_val if status_val else "active",
            "score": score,
            "last_seen": last_win if last_win else "NEVER_PWNED",
            "is_online": is_online
        })
        
    logs_data = [{"msg_en": l[0], "msg_ar": l[1], "time": l[2]} for l in log_rows]
    
    stats_summary = {
        "total_agents": len(agents_data),
        "total_score": total_score,
        "banned_agents": banned_count,
        "maintenance": system_maintenance_mode
    }
    
    return JSONResponse(content={"agents": agents_data, "logs": logs_data, "stats": stats_summary})

@app.get("/admin/{secret_key}/dashboard", response_class=HTMLResponse)
def admin_dashboard(secret_key: str):
    if secret_key != ADMIN_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Access Denied: Invalid Admin Secret Key!"
        )
    try:
        with open("admin.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h3>Error: admin.html file not found in directory!</h3>"

# تشغيل السيرفر تلقائياً على الاستضافة (Render)
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)