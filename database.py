import sqlite3
from datetime import datetime, timezone

DB_FILE = "game_database.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        
        # 1. جدول المستخدمين
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                status TEXT DEFAULT 'active'
            )
        """)
        
        # 2. جدول نقاط اللاعبين
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS player_scores (
                email TEXT PRIMARY KEY,
                score INTEGER DEFAULT 0,
                last_win TIMESTAMP
            )
        """)
        
        # 3. جدول سجل النشاطات
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_en TEXT,
                message_ar TEXT,
                timestamp TEXT
            )
        """)
        
        # إضافة فهارس (Indexes) تسريع البحث والترتيب للمستقبل (آمنة تماماً ولا تؤثر على البيانات)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_email ON activity_logs (email)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_player_score ON player_scores (score DESC)")
        
        # تحديث تلقائي آمن للجداول الحالية (Auto-Migration) لإضافة الأعمدة الجديدة بدون تضارب
        new_columns = [
            ("email", "TEXT"),
            ("action_type", "TEXT"),
            ("difficulty", "TEXT"),
            ("points_earned", "INTEGER DEFAULT 0"),
            ("status", "TEXT"),
            ("device_info", "TEXT")
        ]
        for col_name, col_type in new_columns:
            try:
                cursor.execute(f"ALTER TABLE activity_logs ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass # العمود موجود مسبقاً، يتجاوز التعديل بأمان

        conn.commit()

def log_activity(msg_en: str, msg_ar: str, email: str = None, action_type: str = None, difficulty: str = None, points: int = 0, status_val: str = None, device_info: str = None):
    current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO activity_logs (message_en, message_ar, timestamp, email, action_type, difficulty, points_earned, status, device_info) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (msg_en, msg_ar, current_time, email, action_type, difficulty, points, status_val, device_info))
        conn.commit()