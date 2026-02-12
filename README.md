# TerraGuard

**AI-powered security scanner for infrastructure-as-code**

Scan your Terraform, CloudFormation, Kubernetes, Dockerfiles, and Helm charts for security vulnerabilities, misconfigurations, and hardcoded secrets.

<p align="center">
  <img src="TerraGuard - Infrastructure Security - Intro.png" alt="TerraGuard Welcome Screen" width="800">
</p>

<p align="center">
  <img src="TerraGuard - Infrastructure Security.png" alt="TerraGuard Security Scanner" width="800">
</p>

---

## Features

- **Multi-Provider AI** - Choose from Anthropic, OpenAI, Google, or Groq
- **Privacy Mode** - Anonymizes sensitive data (IPs, ARNs, secrets, domains) before sending to AI — results are deanonymized automatically
- **Secrets Detection** - Finds hardcoded passwords, API keys, and tokens
- **Security Analysis** - Detects open ports, missing encryption, IAM issues
- **Cost Estimation** - AWS resource cost breakdown for Terraform/CloudFormation
- **PDF Reports** - Export detailed security reports
- **Modern UI** - Dark/light themes with glassmorphism design

## Supported Formats

| Format | Extensions | Example Checks |
|--------|------------|----------------|
| Terraform | `.tf`, `.tf.json` | Open security groups, public S3, missing encryption |
| CloudFormation | `.yaml`, `.json`, `.template` | DeletionPolicy, parameter validation |
| Kubernetes | `.yaml`, `.yml` | Privileged containers, root user, missing limits |
| Dockerfile | `Dockerfile` | Root user, latest tags, hardcoded secrets |
| Helm | `.yaml`, `.tpl` | Hardcoded values, missing defaults |

## AI Providers

| Provider | Models | Speed | Cost |
|----------|--------|-------|------|
| Anthropic | Claude Sonnet 4, Claude 3.5 Haiku | Fast | From $0.25/1M tokens |
| OpenAI | GPT-4o, GPT-4o Mini | Fast | From $0.15/1M tokens |
| Google | Gemini 1.5 Pro, Gemini 1.5 Flash | Fast | From $0.075/1M tokens |
| Groq | Llama 3.3 70B, Llama 3.1 8B | Blazing Fast | **Free tier!** |

---

## Quick Start

### 1. Setup

```bash
git clone https://github.com/XionDot/terraguard.git
cd terraguard
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure API Key

**Option A: In-App Setup (Recommended)**

On first launch, a welcome screen guides you through setup:
1. Pick your AI provider (Anthropic, OpenAI, Google, or Groq)
2. Enter your API key — it's saved in your browser for next time
3. You're ready to scan!

You can add or switch providers anytime from the **Settings** panel in the sidebar.

**Option B: Environment Variable**
```bash
cp .env.example .env
# Add your key(s) to .env:
# ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# GOOGLE_API_KEY=AIza...
# GROQ_API_KEY=gsk_...
```

**Get API Keys:**
- [Anthropic Console](https://console.anthropic.com/settings/keys)
- [OpenAI Platform](https://platform.openai.com/api-keys)
- [Google AI Studio](https://aistudio.google.com/app/apikey)
- [Groq Console](https://console.groq.com/keys) (Free!)

### 3. Run

```bash
# Terminal 1: Backend
cd backend && uvicorn main:app --reload --port 8000

# Terminal 2: Frontend
cd frontend && python -m http.server 3000
```

Open **http://localhost:3000**

---

## API Usage

```bash
# Basic scan
curl -X POST http://localhost:8000/review -F "file=@main.tf"

# With specific provider
curl -X POST http://localhost:8000/review \
  -H "X-Provider: groq" \
  -H "X-API-Key: gsk_..." \
  -F "file=@main.tf"

# Generate PDF report
curl -X POST http://localhost:8000/review/pdf \
  -F "file=@main.tf" -o report.pdf
```

**Headers:**
- `X-API-Key` - Your API key (optional if set in `.env`)
- `X-Provider` - `anthropic`, `openai`, `google`, or `groq`
- `X-Model` - Specific model (optional)

---

## Tech Stack

- **Backend**: FastAPI + Python
- **Frontend**: Vanilla HTML/CSS/JS
- **AI**: Multi-provider (Anthropic, OpenAI, Google, Groq)

## License

MIT

## 💰 You can help me by Donating
  [![BuyMeACoffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/cr4ne) 

