from audit_service import log_action
from db import SessionLocal
from models import Concern, Student, utcnow
from scoring import clean_student, score_student

MAX_REQUESTS = 2


def create_concern(student_id, message, corrected_name=None,
                   corrected_email=None, corrected_phone=None,
                   corrected_aapar_id=None, ip_address=None, user_id=None):
    """A correction request for a student. Maximum 2 per student, one pending at a time."""
    with SessionLocal() as db:
        if not db.get(Student, student_id):
            return {"ok": False, "error": "Student not found"}
        if db.query(Concern).filter_by(student_id=student_id).count() >= MAX_REQUESTS:
            return {"ok": False, "error": "Maximum 2 requests allowed"}
        if db.query(Concern).filter_by(student_id=student_id, status="pending").count():
            return {"ok": False, "error": "A request is already pending"}
        c = Concern(student_id=student_id, message=message,
                    corrected_name=corrected_name, corrected_email=corrected_email,
                    corrected_phone=corrected_phone, corrected_aapar_id=corrected_aapar_id)
        db.add(c)
        db.commit()
        new_id = c.id

    log_action(user_id, "CONCERN_CREATED", "concern", new_id,
               f"Student {student_id} requested review", ip_address)
    return {"ok": True, "concern_id": new_id}


def list_concerns(status=None):
    """For admins: all requests (optional status filter)."""
    with SessionLocal() as db:
        q = db.query(Concern, Student.name).join(Student, Student.id == Concern.student_id)
        if status:
            q = q.filter(Concern.status == status)
        rows = q.order_by(Concern.created_at.desc()).all()
    return [{
        "id": c.id, "student_id": c.student_id, "name": name, "message": c.message,
        "corrected_name": c.corrected_name, "corrected_email": c.corrected_email,
        "corrected_phone": c.corrected_phone, "corrected_aapar_id": c.corrected_aapar_id,
        "status": c.status, "admin_note": c.admin_note,
        "created_at": c.created_at.isoformat() + "Z" if c.created_at else None,
    } for c, name in rows]


def review_concern(concern_id, admin_id, approve, admin_note=None, ip_address=None):
    """Admin approves/rejects. Approval applies the corrections AND re-runs fraud screening,
    so a correction cannot be used to dodge the duplicate checks."""
    new_status = "approved" if approve else "rejected"
    with SessionLocal() as db:
        c = db.query(Concern).filter_by(id=concern_id, status="pending").first()
        if not c:
            return {"ok": False, "error": "Concern not found or already reviewed"}

        c.status = new_status
        c.admin_note = admin_note
        c.reviewed_by = admin_id
        c.reviewed_at = utcnow()
        student_id = c.student_id

        if approve:
            s = db.get(Student, student_id)
            if c.corrected_name:
                s.name = c.corrected_name
            if c.corrected_email:
                s.email = c.corrected_email
            if c.corrected_phone:
                s.phone = c.corrected_phone
            if c.corrected_aapar_id:
                s.aapar_id = c.corrected_aapar_id
            cleaned = clean_student({"name": s.name, "aapar_id": s.aapar_id, "email": s.email,
                                     "phone": s.phone, "institution": s.institution})
            s.name, s.aapar_id, s.email, s.phone = (
                cleaned["name"], cleaned["aapar_id"], cleaned["email"], cleaned["phone"])
            s.risk_score, _flag, s.reason = score_student(db, cleaned, exclude_id=s.id)
            s.status = "pending"  # details changed, so an officer must decide again
        db.commit()

    log_action(admin_id, f"CONCERN_{new_status.upper()}", "concern",
               concern_id, admin_note, ip_address)
    return {"ok": True, "status": new_status, "student_id": student_id}
