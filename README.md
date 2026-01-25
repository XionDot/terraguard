# ☁️ Cloud Architecture Review Agent

AI-powered Terraform code review for security, cost, and best practices.

## Quick Start

### 1. Setup

```bash
cd cloud-arch-agent
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure API Key

```bash
cp .env.example .env
# Edit .env and add your Anthropic API key
```

### 3. Run Backend

```bash
cd backend
python main.py
# Or: uvicorn main:app --reload
```

API runs at http://localhost:8000

### 4. Run Frontend

```bash
cd frontend
streamlit run app.py
```

App runs at http://localhost:8501

## API Endpoints

### POST /review
Upload a Terraform file for review.

```bash
curl -X POST "http://localhost:8000/review" \
  -F "file=@main.tf"
```

### POST /review/text
Send Terraform content as text.

```bash
curl -X POST "http://localhost:8000/review/text" \
  -H "Content-Type: application/json" \
  -d '{"terraform_content": "resource \"aws_instance\" \"example\" {}"}'
```

## What It Reviews

- 🔴 **Security** - Open ports, missing encryption, IAM issues
- 💰 **Cost** - Oversized instances, unused resources
- 📋 **Best Practices** - Hardcoded values, missing tags
- 🛡️ **Reliability** - Single points of failure, no backups

## Tech Stack

- **Backend**: FastAPI + Anthropic Claude
- **Frontend**: Streamlit
- **AI**: Claude claude-sonnet-4-20250514

## Next Steps

- [ ] Add Stripe for payments
- [ ] Add user accounts
- [ ] Support more file types (CloudFormation, Pulumi)
- [ ] Add GitHub integration
- [ ] Deploy to Vercel/Railway
