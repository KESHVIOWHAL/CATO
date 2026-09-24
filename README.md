# CATO — Context-Aware Trust Orchestrator
**SIH 2026 · Problem SIH26194 · ThinkTank**

> Protecting AI-Assisted Software Development from Prompt to Production

---

## How to Run

Open **two terminals**:

**Terminal 1 — Backend**
```
cd cato/backend/app
python -m uvicorn main:app --reload --port 8000
```
Or double-click `start_backend.bat`

**Terminal 2 — Frontend**
```
cd cato/frontend
npm run dev
```
Or double-click `start_frontend.bat`

Then open: **http://localhost:5173**

---

## Demo Flow (for judges)

### BEFORE — Unsafe AI-generated code
1. Select **AI-Demo-App (UNSAFE)**
2. Click **ANALYZE PROJECT**
3. See: Secret Detection ❌ · SAST ❌ · Dependencies ❌ · Tests ✓
4. Decision: **BLOCK — HIGH RISK**
5. Click **View Trust Certificate** → see Certificate ID + SHA-256 hash
6. Go to **Blockchain** tab → see the block recorded
7. Copy the hash and click **Verify** → confirmed on chain

### AFTER — Fixed code
1. Select **AI-Demo-App (FIXED)**
2. Click **ANALYZE PROJECT**
3. See: All checks ✓
4. Decision: **APPROVE — LOW RISK**
5. New certificate with new hash
6. New blockchain block

**Key message:** We did not change the trust decision. We changed the software evidence. CATO re-evaluated and produced a different decision.

---

## What Is Real vs Demo Mode

| Component | Mode | Notes |
|-----------|------|-------|
| Secret Detection | DEMO | Pre-defined findings (Gitleaks not installed) |
| SAST | DEMO | Pre-defined findings (Semgrep not installed) |
| Dependency Scan | DEMO | Pre-defined findings (OSV-Scanner not installed) |
| Functional Tests | **LIVE** | Runs real pytest |
| Decision Engine | **LIVE** | Real rule-based logic |
| Trust Certificate | **LIVE** | Real SHA-256 hash |
| Blockchain | **LIVE** | In-memory SHA-256 linked chain (no external node) |

---

## Architecture

```
Developer / AI Code
        ↓
   CATO Orchestrator
        ↓
  Security Verification
  (Secrets · SAST · Deps · Tests)
        ↓
  Evidence Collection
        ↓
  Policy Decision Engine
        ↓
  APPROVE / REVIEW / BLOCK
        ↓
  Trust Certificate
        ↓
  SHA-256 Hash
        ↓
  Blockchain Registry
        ↓
  Verification
```

---

## Known Limitations (Prototype)

- Security scanners run in DEMO MODE (install Gitleaks/Semgrep/OSV for live scanning)
- Blockchain is in-memory — resets on backend restart
- No authentication / multi-user
- No persistent database
- No PDF certificate export
