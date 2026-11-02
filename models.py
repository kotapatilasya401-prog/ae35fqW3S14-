from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Float, Text, DateTime, ForeignKey

from db import Base


def utcnow():
    """Naive UTC time (works the same on SQLite and PostgreSQL)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="officer", nullable=False)


class Student(Base):
    __tablename__ = "students"
    id = Column(Integer, primary_key=True)
    student_code = Column(String, unique=True, index=True)  # e.g. NGI-2026-001
    name = Column(String)
    aapar_id = Column(String, index=True)
    email = Column(String, index=True)
    phone = Column(String, index=True)
    institution = Column(String)
    risk_score = Column(Float, default=0.0)
    status = Column(String, default="verified")
    reason = Column(String, default="")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False, index=True)
    entity_type = Column(String)
    entity_id = Column(Integer, index=True)
    details = Column(Text)
    ip_address = Column(String)
    created_at = Column(DateTime, default=utcnow, index=True)


class Concern(Base):
    __tablename__ = "concerns"
    id = Column(Integer, primary_key=True)
    student_id = Column(Integer, ForeignKey("students.id"), nullable=False, index=True)
    message = Column(Text, nullable=False)
    corrected_name = Column(String)
    corrected_email = Column(String)
    corrected_phone = Column(String)
    corrected_aapar_id = Column(String)
    status = Column(String, default="pending", nullable=False, index=True)
    admin_note = Column(Text)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=utcnow)
    reviewed_at = Column(DateTime)
