# AI Agent Identification Framework — v2.0 (Clean)

## Project Structure

```
FPAIF_Clean/
├── app.py              # FastAPI server
├── db.py               # SQLite database + metrics tracking
├── identity.py         # DID + SHA256 Verifiable Credentials
├── trust.py            # ABAC policy
├── run_tests.py        # Full metric test suite (all 13 metrics)
├── requirements.txt
└── templates/
    └── audit_logs.html
```

---

## Local Quick Start

```bash
pip install -r requirements.txt

# Terminal 1 — start server
uvicorn app:app --reload

# Terminal 2 — run all metric tests
python run_tests.py
```

Output: all numbers printed to terminal + saved to `metrics_numbers.json`

---

## Oracle Cloud Free Tier — Step by Step

### 1. Create Oracle Account
- Go to https://cloud.oracle.com
- Sign up for Always Free tier (no credit card charges for Always Free resources)

### 2. Create VM Instance
- Go to Compute → Instances → Create Instance
- Image: Ubuntu 22.04
- Shape: VM.Standard.E2.1.Micro (Always Free)
- Generate SSH key pair, download the private key

### 3. SSH Into VM
```bash
ssh -i <your-private-key.pem> ubuntu@<oracle-public-ip>
```

### 4. Setup on Oracle VM
```bash
sudo apt update && sudo apt install python3-pip git -y

git clone https://github.com/muzahidsife/AI_Agent_Identification_Framework_Prototype
cd AI_Agent_Identification_Framework_Prototype

pip3 install -r requirements.txt
```

### 5. Open Port 8000
- In Oracle Console → Networking → Virtual Cloud Network → Security Lists
- Add Ingress Rule: TCP, port 8000, source 0.0.0.0/0

### 6. Start Server (background)
```bash
nohup uvicorn app:app --host 0.0.0.0 --port 8000 > server.log 2>&1 &
```

### 7. Run Tests
```bash
# Default: 1000 users
python3 run_tests.py

# Custom user count
python3 run_tests.py --users 500

# If running from your LOCAL machine against Oracle
python3 run_tests.py --url http://<oracle-public-ip>:8000 --users 1000
```

### 8. Get Your Numbers
```bash
cat metrics_numbers.json
```

Copy the numbers into matplotlib on your PC to make graphs.

---

## Metrics Covered

| # | Metric | How Tested |
|---|--------|------------|
| 1 | Auth Success Rate | 80 valid + 20 wrong creds → count |
| 2 | Auth Failure Rate | same batch → count failures |
| 3 | Auth Time (ms) | time.time() before/after each call |
| 4 | Unauthorized vs Authorized Ratio | guest agents vs admin agents |
| 5 | DDoS Block Rate | 200 rapid requests, same IP |
| 6 | Session Hijacking Denial Rate | 50 fake UUIDs as tokens |
| 7 | Log Time (ms) | server-measured log write latency |
| 8 | Big Agent Auth Time | 4 scenarios with increasing name size |
| 9 | Encryption | SHA256 verified in output |
| 10 | Load — 1000 concurrent registrations | ThreadPoolExecutor, 100 workers |
| 11 | Load — Auth throughput (rps) | concurrent auth after reg |
| 12 | Load — Response time under load | min/avg/median/p95/max |
| 13 | Session Token Expiry | expires_at tracked per session |

---

## Web Pages

| URL | Page |
|-----|------|
| `/` | Home with nav |
| `/register_agent` | Register form |
| `/audit_logs` | Logs with timing columns |
| `/docs` | Swagger API docs |
| `/test_flow` | Quick end-to-end test |
| `/api/audit_logs` | JSON logs |
