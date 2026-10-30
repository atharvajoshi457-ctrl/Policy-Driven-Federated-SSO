from datetime import datetime, timezone
from pathlib import Path
import base64, hashlib, hmac, json, os, sqlite3, time

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "federation.db"
SECRET = os.getenv("DEMO_SIGNING_SECRET", "classroom-only-change-this-secret").encode()
TOKEN_TTL_SECONDS = 1800

app = FastAPI(title="Policy-Driven Federated SSO", version="1.0.0",
              description="Educational cross-organization identity federation prototype")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")

USERS = {
    "alice": {"name": "Alice Sharma", "email": "alice@home.example", "organization": "home-university",
              "role": "researcher", "mfa": True},
    "bob": {"name": "Bob Mehta", "email": "bob@home.example", "organization": "home-university",
            "role": "student", "mfa": True},
    "carol": {"name": "Carol Rao", "email": "carol@home.example", "organization": "home-university",
              "role": "researcher", "mfa": False},
}
PARTNERS = [
    {"id": "partner-lab", "name": "Partner Research Lab", "issuer": "home-university",
     "audience": "partner-lab", "status": "trusted", "resources": ["research-portal", "public-library"]},
    {"id": "partner-clinic", "name": "Partner Health Institute", "issuer": "home-university",
     "audience": "partner-clinic", "status": "trusted", "resources": ["public-library"]},
]
POLICIES = {
    "research-portal": {"allowed_roles": ["researcher"], "mfa_required": True,
                        "allowed_orgs": ["home-university"], "description": "Restricted research workspace"},
    "public-library": {"allowed_roles": ["student", "researcher"], "mfa_required": False,
                       "allowed_orgs": ["home-university"], "description": "Shared public library"},
}

def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            username TEXT, partner_id TEXT, resource TEXT, decision TEXT,
            reason TEXT, subject TEXT)""")

def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def issue_token(user_id: str) -> str:
    user = USERS[user_id]
    now = int(time.time())
    payload = {"sub": user_id, "name": user["name"], "email": user["email"],
               "iss": user["organization"], "iat": now, "exp": now + TOKEN_TTL_SECONDS,
               "role": user["role"], "mfa": user["mfa"]}
    body = b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64(hmac.new(SECRET, body.encode(), hashlib.sha256).digest())
    return body + "." + sig

def validate_token(token: str):
    try:
        body, signature = token.split(".", 1)
        expected = b64(hmac.new(SECRET, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("Signature validation failed")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if payload["exp"] < int(time.time()):
            raise ValueError("Identity token expired")
        if payload["iss"] != "home-university":
            raise ValueError("Untrusted identity issuer")
        return payload
    except Exception as exc:
        raise ValueError(str(exc))

def record(payload, partner_id, resource, decision, reason, subject):
    with db() as conn:
        conn.execute("""INSERT INTO audit(timestamp, username, partner_id, resource, decision, reason, subject)
                        VALUES(?,?,?,?,?,?,?)""",
                     (datetime.now(timezone.utc).isoformat(), payload.get("sub", "unknown"),
                      partner_id, resource, decision, reason, subject))

class LoginRequest(BaseModel):
    username: str

class AccessRequest(BaseModel):
    token: str
    partner_id: str
    resource: str

@app.on_event("startup")
def startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
def home():
    return (BASE_DIR / "app" / "static" / "index.html").read_text(encoding="utf-8")

@app.get("/health")
def health():
    return {"status": "ok", "service": "policy-driven-federated-sso"}

@app.get("/api/users")
def get_users():
    return [{"id": k, "name": v["name"], "role": v["role"], "mfa": v["mfa"]}
            for k, v in USERS.items()]

@app.get("/api/partners")
def get_partners():
    return PARTNERS

@app.get("/api/policies")
def get_policies():
    return POLICIES

@app.post("/api/login")
def login(req: LoginRequest):
    if req.username not in USERS:
        raise HTTPException(status_code=404, detail="Unknown demo identity")
    token = issue_token(req.username)
    return {"token": token, "expires_in": TOKEN_TTL_SECONDS,
            "identity": {"username": req.username, **USERS[req.username]}}

@app.post("/api/access")
def request_access(req: AccessRequest):
    try:
        claims = validate_token(req.token)
    except ValueError as exc:
        record({"sub": "unknown"}, req.partner_id, req.resource, "DENY", str(exc), "gateway")
        raise HTTPException(status_code=401, detail=f"Federation validation failed: {exc}")

    partner = next((p for p in PARTNERS if p["id"] == req.partner_id), None)
    if not partner or partner["status"] != "trusted":
        record(claims, req.partner_id, req.resource, "DENY", "Partner is not in trust registry", "gateway")
        raise HTTPException(status_code=403, detail="Partner is not trusted")
    if partner["issuer"] != claims["iss"] or partner["audience"] != req.partner_id:
        record(claims, req.partner_id, req.resource, "DENY", "Issuer/audience mismatch", "gateway")
        raise HTTPException(status_code=403, detail="Federation trust validation failed")
    if req.resource not in partner["resources"] or req.resource not in POLICIES:
        record(claims, req.partner_id, req.resource, "DENY", "Resource is not registered", "gateway")
        raise HTTPException(status_code=404, detail="Resource is not registered for this partner")

    # Claim transformation: normalize external identity attributes for partner-side policy.
    partner_claims = {"subject": claims["sub"], "display_name": claims["name"],
                      "email": claims["email"], "home_org": claims["iss"],
                      "partner_role": claims["role"], "mfa_verified": bool(claims["mfa"])}
    policy = POLICIES[req.resource]
    reasons = []
    if partner_claims["home_org"] not in policy["allowed_orgs"]:
        reasons.append("home organization is not allowed")
    if partner_claims["partner_role"] not in policy["allowed_roles"]:
        reasons.append(f"role '{partner_claims['partner_role']}' is not permitted")
    if policy["mfa_required"] and not partner_claims["mfa_verified"]:
        reasons.append("MFA is required")
    decision = "DENY" if reasons else "ALLOW"
    reason = "; ".join(reasons) if reasons else "All federation and authorization checks passed"
    record(claims, req.partner_id, req.resource, decision, reason, "policy-decision-point")
    return {"decision": decision, "reason": reason, "partner": partner["name"],
            "resource": req.resource, "claims_released": partner_claims if decision == "ALLOW" else {},
            "policy": policy, "audit_recorded": True}

@app.get("/api/audit")
def audit():
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100").fetchall()
    return [dict(row) for row in rows]
