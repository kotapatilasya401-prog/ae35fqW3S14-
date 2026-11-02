import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
import networkx as nx
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import concern_service
from audit_service import log_action, get_audit_logs, get_student_logs
from db import engine, SessionLocal, Base
from models import User, Student
from scoring import clean_student, score_student

# --- settings (set these as environment variables when you deploy) ---
SECRET = os.getenv("JWT_SECRET") or secrets.token_urlsafe(48)  # set JWT_SECRET so logins survive restarts
ALGO = "HS256"
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]

Base.metadata.create_all(engine)

oauth2 = OAuth2PasswordBearer(tokenUrl="auth/login")
oauth2_optional = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)


def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def verify_password(p: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), hashed.encode())
    except ValueError:
        return False


# --- request / response shapes ---
class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=72)
    role: str = "officer"


class StudentIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    aapar_id: str = Field(min_length=1, max_length=40)
    email: str = Field(min_length=1, max_length=120)
    phone: str = Field(min_length=1, max_length=30)
    institution: str = Field(min_length=1, max_length=120)


class StudentOut(BaseModel):
    id: int
    student_code: Optional[str] = None
    name: str
    aapar_id: str
    email: str
    phone: str
    institution: str
    risk_score: float
    status: str
    reason: str
    model_config = {"from_attributes": True}


class StatusIn(BaseModel):
    status: str


class ConcernIn(BaseModel):
    student_id: int
    message: str = Field(min_length=1, max_length=2000)
    corrected_name: Optional[str] = None
    corrected_email: Optional[str] = None
    corrected_phone: Optional[str] = None
    corrected_aapar_id: Optional[str] = None


class ReviewIn(BaseModel):
    approve: bool
    admin_note: Optional[str] = None


# --- helpers ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def client_ip(request: Request):
    # Behind a host's proxy the real address is in X-Forwarded-For.
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def _load_user(token: str, db: Session):
    try:
        username = jwt.decode(token, SECRET, algorithms=[ALGO])["sub"]
    except (jwt.PyJWTError, KeyError):
        raise HTTPException(401, "Invalid token")
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(401, "Invalid token: user not found")
    return user


def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)):
    return _load_user(token, db)


def optional_user(token: Optional[str] = Depends(oauth2_optional), db: Session = Depends(get_db)):
    if not token:
        return None
    try:
        return _load_user(token, db)
    except HTTPException:
        return None


def admin_only(user: User = Depends(current_user)):
    if user.role != "admin":
        raise HTTPException(403, "Admins only")
    return user


def officer_only(user: User = Depends(current_user)):
    if user.role != "officer":
        raise HTTPException(403, "Officers only")
    return user


# --- app ---
app = FastAPI(title="NextGen API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", include_in_schema=False)
def health():
    return {"ok": True}


@app.post("/auth/register")
def register(u: UserIn, db: Session = Depends(get_db), caller: Optional[User] = Depends(optional_user)):
    if u.role not in ("officer", "admin"):
        raise HTTPException(422, "Invalid role")
    if db.query(User).filter_by(username=u.username).first():
        raise HTTPException(400, "Username taken")
    # Anyone may create the FIRST admin; after that only a signed-in officer can create admins.
    if u.role == "admin" and db.query(User).filter_by(role="admin").first():
        if not caller or caller.role != "officer":
            raise HTTPException(403, "Only a signed-in officer can create another admin account")
    db.add(User(username=u.username, hashed_password=hash_password(u.password), role=u.role))
    db.commit()
    return {"message": "created"}


@app.post("/auth/login")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    ip = client_ip(request)
    user = db.query(User).filter_by(username=form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        log_action(user.id if user else None, "LOGIN_FAILED", "user", user.id if user else None,
                   f"username={form.username[:50]}", ip)
        raise HTTPException(401, "Wrong credentials")
    token = jwt.encode(
        {"sub": user.username, "role": user.role,
         "exp": datetime.now(timezone.utc) + timedelta(hours=12)},
        SECRET, ALGO,
    )
    log_action(user.id, "LOGIN", "user", user.id, None, ip)
    return {"access_token": token, "token_type": "bearer", "role": user.role}


@app.post("/students", response_model=StudentOut)
def add_student(s: StudentIn, request: Request, db: Session = Depends(get_db),
                user: User = Depends(officer_only)):
    data = clean_student(s.model_dump())
    score, _flag, reason = score_student(db, data)  # risk score is advice; the officer decides
    row = Student(**data, risk_score=score, status="pending", reason=reason)
    db.add(row)
    db.flush()  # gives us row.id
    row.student_code = f"NGI-{datetime.now().year}-{row.id:03d}"
    db.commit()
    db.refresh(row)
    log_action(user.id, "ADD_STUDENT", "student", row.id,
               f"code={row.student_code}; status={row.status}", client_ip(request))
    return row


@app.get("/students", response_model=list[StudentOut])
def list_students(status: Optional[str] = None, db: Session = Depends(get_db), _=Depends(current_user)):
    q = db.query(Student)
    if status:
        q = q.filter_by(status=status)
    return q.order_by(Student.id.desc()).all()


@app.patch("/students/{student_id}/status")
def set_status(student_id: int, body: StatusIn, request: Request,
               db: Session = Depends(get_db), user: User = Depends(officer_only)):
    if body.status not in ("accepted", "rejected"):
        raise HTTPException(422, "Invalid status")
    s = db.get(Student, student_id)
    if not s:
        raise HTTPException(404, "Student not found")
    old = s.status
    s.status = body.status
    db.commit()
    log_action(user.id, "STATUS_CHANGE", "student", s.id, f"{old} -> {body.status}", client_ip(request))
    return {"id": s.id, "status": s.status}


@app.get("/verify/{code}")
def verify(code: str, request: Request, method: str = "manual", location: str = "",
           db: Session = Depends(get_db), user: User = Depends(officer_only)):
    """Look up a student by the ID inside their QR code. Every lookup is logged."""
    code = code.strip().upper()
    method = method if method in ("qr", "manual") else "manual"
    location = location.replace(";", ",").strip()[:80] or "unknown"
    ip = client_ip(request)
    s = db.query(Student).filter_by(student_code=code).first()
    if not s:
        log_action(user.id, "VERIFY_NOT_FOUND", "student", None, f"code={code[:40]}", ip)
        raise HTTPException(404, "Student ID not found")
    log_action(user.id, "VERIFY_SCAN", "student", s.id, f"method={method}; location={location}", ip)
    return {
        "student": {"student_code": s.student_code, "name": s.name, "institution": s.institution},
        "audit_log": get_student_logs(s.id),
    }


@app.get("/audit-logs")
def audit_logs(limit: int = 50, _=Depends(admin_only)):
    return get_audit_logs(limit)


@app.get("/admin/stats")
def stats(db: Session = Depends(get_db), _=Depends(current_user)):
    total = db.query(Student).count()
    flagged = db.query(Student).filter(Student.risk_score >= 0.5).count()
    return {
        "total": total,
        "pending": db.query(Student).filter_by(status="pending").count(),
        "accepted": db.query(Student).filter_by(status="accepted").count(),
        "rejected": db.query(Student).filter_by(status="rejected").count(),
        "flagged": flagged,
        "flag_rate": round(flagged / total, 2) if total else 0,
    }


@app.get("/graph")
def graph(db: Session = Depends(get_db), _=Depends(current_user)):
    students = db.query(Student).all()
    G = nx.MultiGraph()
    for s in students:
        G.add_node(s.id, name=s.name, status=s.status, flagged=(s.risk_score or 0) >= 0.5)
    for field in ("phone", "email", "aapar_id"):
        groups = {}
        for s in students:
            v = (getattr(s, field) or "").strip().lower()
            if v:
                groups.setdefault(v, []).append(s.id)
        for ids in groups.values():
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    G.add_edge(ids[i], ids[j], reason=f"same {field}")
    clusters = [sorted(c) for c in nx.connected_components(G) if len(c) > 1]
    return {
        "nodes": [{"id": n, **d} for n, d in G.nodes(data=True)],
        "edges": [{"source": u, "target": v, "reason": d["reason"]}
                  for u, v, d in G.edges(data=True)],
        "suspicious_clusters": clusters,
    }


# --- correction requests (backend only; the web page has no screen for these yet) ---
@app.post("/concerns")
def create_concern(body: ConcernIn, request: Request, user: User = Depends(officer_only)):
    r = concern_service.create_concern(
        body.student_id, body.message, body.corrected_name, body.corrected_email,
        body.corrected_phone, body.corrected_aapar_id, client_ip(request), user.id)
    if not r["ok"]:
        raise HTTPException(400, r["error"])
    return r


@app.get("/concerns")
def list_concerns(status: Optional[str] = None, _=Depends(officer_only)):
    return concern_service.list_concerns(status)


@app.post("/concerns/{concern_id}/review")
def review_concern(concern_id: int, body: ReviewIn, request: Request, user: User = Depends(officer_only)):
    r = concern_service.review_concern(concern_id, user.id, body.approve, body.admin_note, client_ip(request))
    if not r["ok"]:
        raise HTTPException(404, r["error"])
    return r


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(os.path.join(os.path.dirname(__file__), "index.html"))
