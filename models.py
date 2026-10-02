from pydantic import BaseModel, EmailStr, Field

class AgentData(BaseModel):
    email: EmailStr  # يضمن تلقائياً أن الإدخال بريد إلكتروني صحيح
    password: str = Field(..., min_length=6)  # يمنع كلمات المرور الأقل من 6 أحرف

class AgentEmailData(BaseModel):
    email: EmailStr