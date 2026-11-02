import re
from difflib import SequenceMatcher

import numpy as np
from sklearn.ensemble import IsolationForest

# The anomaly model is retrained on every request, so keep its training set small.
MAX_TRAIN = 300


def _norm(v):
    return (v or "").strip().lower()


def _phone(v):
    digits = re.sub(r"\D", "", v or "")
    if len(digits) == 12 and digits.startswith("91"):  # +91 prefix
        digits = digits[2:]
    return digits


def _sim(a, b):
    return SequenceMatcher(None, _norm(a), _norm(b)).ratio()


def build_features(s, others):
    sid, sph, sem = _norm(s["aapar_id"]), _phone(s["phone"]), _norm(s["email"])
    # Blank values never count as a "match".
    same_id = sum(1 for o in others if sid and _norm(o["aapar_id"]) == sid)
    same_phone = sum(1 for o in others if sph and _phone(o["phone"]) == sph)
    same_email = sum(1 for o in others if sem and _norm(o["email"]) == sem)
    inst = _norm(s["institution"])
    max_sim = max((_sim(o["name"], s["name"]) for o in others
                   if _norm(o["institution"]) == inst), default=0.0)
    bad_phone = 0 if re.fullmatch(r"[6-9]\d{9}", sph) else 1
    bad_email = 0 if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", sem) else 1
    return [same_id, same_phone, same_email, max_sim, bad_phone, bad_email]


def predict(student: dict, others: list[dict]) -> dict:
    same_id, same_phone, same_email, max_sim, bad_phone, bad_email = build_features(student, others)
    reasons = []
    risk = 0.0

    if same_id:
        risk += 0.5
        reasons.append(f"AAPAR ID already used by {same_id} record(s)")
    if same_phone:
        risk += 0.25
        reasons.append(f"Phone number shared with {same_phone} record(s)")
    if same_email:
        risk += 0.2
        reasons.append(f"Email shared with {same_email} record(s)")
    if max_sim > 0.9:
        risk += 0.3
        reasons.append(f"Name {int(max_sim * 100)}% similar to another student at the same institution")
    if bad_phone:
        risk += 0.25
        reasons.append("Phone number format looks invalid")
    if bad_email:
        risk += 0.25
        reasons.append("Email format looks invalid")

    anomaly = False
    pool = others[-MAX_TRAIN:]
    if len(pool) >= 10:
        X = np.array([build_features(o, [x for x in pool if x is not o]) for o in pool])
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42).fit(X)
        anomaly = bool(model.predict([build_features(student, pool)])[0] == -1)
        if anomaly:
            risk += 0.15
            reasons.append("Record is statistically unusual compared with existing data")

    return {
        "risk_score": round(min(risk, 1.0), 2),
        "is_duplicate": bool(same_id or same_phone or same_email or max_sim > 0.9),
        "anomaly": anomaly,
        "reasons": reasons,
    }
