# Policy-Driven Federated Single Sign-On (SSO)

A runnable educational prototype demonstrating secure cross-organization access through identity federation and policy-based authorization.

## What it demonstrates
- Two simulated organizations (Home University and Partner Research Lab)
- A home identity provider (IdP) issuing a signed demo identity token
- A federation gateway validating the token and the partner's trust registration
- Claim mapping / transformation
- A policy decision point (PDP) evaluating role, organization, MFA status and requested resource
- A protected partner application
- SQLite audit events for successful and denied access

> **Security note:** This is a classroom prototype, not production-ready identity infrastructure. It uses a local HMAC demo token and simulated login/MFA. Do not use real passwords, real personal data, or expose it to the public internet. Production systems should use a mature IdP and standards-compliant OIDC/SAML libraries, TLS, key rotation, secure session handling, strong MFA, and hardened policy administration.

## Requirements
- Python 3.10+
- pip

## Run locally
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000

## Demo walkthrough
1. Choose a demo user and sign in at the Home Organization.
2. Select a partner resource and request access.
3. The gateway validates the demo token and partner trust configuration.
4. The PDP applies the policy. Try:
   - `alice` + `researcher` + MFA enabled -> allowed for the research portal.
   - `bob` + `student` -> denied for the restricted research portal.
   - `carol` + MFA disabled -> denied because MFA is required.
5. Open **Audit Log** to inspect decisions.

## API endpoints
- `GET /api/partners` — trusted partner organizations
- `GET /api/users` — demo identities
- `POST /api/login` — issue a demo identity token
- `POST /api/access` — federation and policy evaluation
- `GET /api/audit` — recent audit events
- `GET /health` — health check

## GitHub
Create an empty repository on GitHub, then from this folder:
```bash
git init
git add .
git commit -m "Initial federated SSO project"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

## Suggested report description
The prototype models a policy-driven federation workflow. A user authenticates with a home organization, receives a signed identity assertion, and requests a partner resource. The federation gateway checks partner trust and transforms claims. The policy decision point evaluates authorization attributes before the protected application grants access. Each decision is recorded for auditability.
