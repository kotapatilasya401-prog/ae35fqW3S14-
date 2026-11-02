import re

from sqlalchemy.orm import Session

from ml_service import predict
from models import Student


def clean_student(d: dict) -> dict:
    """Trim and normalise input so duplicate checks are reliable."""
    return {
        "name": d["name"].strip(),
        "aapar_id": d["aapar_id"].strip(),
        "email": d["email"].strip().lower(),
        "phone": re.sub(r"\D", "", d["phone"]),
        "institution": d["institution"].strip(),
    }


def score_student(db: Session, data: dict, exclude_id=None):
    q = db.query(Student)
    if exclude_id is not None:
        q = q.filter(Student.id != exclude_id)
    others = [
        dict(name=o.name, aapar_id=o.aapar_id, email=o.email,
             phone=o.phone, institution=o.institution)
        for o in q.all()
    ]
    result = predict(data, others)
    score = result["risk_score"]
    status = "flagged" if score >= 0.5 else "verified"
    return score, status, "; ".join(result["reasons"])
