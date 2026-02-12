"""
Cloud Architecture Review Agent - Backend API
Supports: Terraform, CloudFormation, Kubernetes, Dockerfile, Helm
Multi-provider AI support: Anthropic, OpenAI, Google, Groq
"""
import os
import json
import re
from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional, Union
from dotenv import load_dotenv
from anonymizer import ContentAnonymizer

# AI Provider SDKs
from anthropic import Anthropic
import openai
import google.generativeai as genai
from groq import Groq

load_dotenv()

app = FastAPI(title="Cloud Architecture Review Agent")

# Provider configurations
PROVIDERS = {
    "anthropic": {
        "name": "Anthropic",
        "key_prefix": "sk-ant-",
        "env_var": "ANTHROPIC_API_KEY",
        "models": {
            "claude-sonnet-4-20250514": {"name": "Claude Sonnet 4", "speed": "Fast", "cost": "$3/1M tokens"},
            "claude-3-5-haiku-20241022": {"name": "Claude 3.5 Haiku", "speed": "Very Fast", "cost": "$0.25/1M tokens"},
        },
        "default_model": "claude-sonnet-4-20250514"
    },
    "openai": {
        "name": "OpenAI",
        "key_prefix": "sk-",
        "env_var": "OPENAI_API_KEY",
        "models": {
            "gpt-4o": {"name": "GPT-4o", "speed": "Fast", "cost": "$2.50/1M tokens"},
            "gpt-4o-mini": {"name": "GPT-4o Mini", "speed": "Very Fast", "cost": "$0.15/1M tokens"},
        },
        "default_model": "gpt-4o"
    },
    "google": {
        "name": "Google",
        "key_prefix": "AI",
        "env_var": "GOOGLE_API_KEY",
        "models": {
            "gemini-1.5-pro": {"name": "Gemini 1.5 Pro", "speed": "Fast", "cost": "$1.25/1M tokens"},
            "gemini-1.5-flash": {"name": "Gemini 1.5 Flash", "speed": "Very Fast", "cost": "$0.075/1M tokens"},
        },
        "default_model": "gemini-1.5-pro"
    },
    "groq": {
        "name": "Groq",
        "key_prefix": "gsk_",
        "env_var": "GROQ_API_KEY",
        "models": {
            "llama-3.3-70b-versatile": {"name": "Llama 3.3 70B", "speed": "Blazing Fast", "cost": "Free tier available"},
            "llama-3.1-8b-instant": {"name": "Llama 3.1 8B", "speed": "Ultra Fast", "cost": "Free tier available"},
        },
        "default_model": "llama-3.3-70b-versatile"
    }
}

# Check for any configured API keys in environment
def get_env_api_keys():
    """Get all API keys configured in environment."""
    keys = {}
    for provider, config in PROVIDERS.items():
        key = os.getenv(config["env_var"])
        if key:
            keys[provider] = key
    return keys

ENV_API_KEYS = get_env_api_keys()

# Supported config types
CONFIG_TYPES = {
    "terraform": {
        "extensions": [".tf", ".tf.json"],
        "markers": ["resource ", "provider ", "terraform {"],
        "name": "Terraform",
        "language": "hcl"
    },
    "cloudformation": {
        "extensions": [".yaml", ".yml", ".json", ".template"],
        "markers": ["AWSTemplateFormatVersion", "Resources:", "AWS::"],
        "name": "CloudFormation",
        "language": "yaml"
    },
    "kubernetes": {
        "extensions": [".yaml", ".yml"],
        "markers": ["apiVersion:", "kind:", "metadata:"],
        "name": "Kubernetes",
        "language": "yaml"
    },
    "dockerfile": {
        "extensions": ["Dockerfile", ".dockerfile"],
        "markers": ["FROM ", "RUN ", "CMD ", "ENTRYPOINT "],
        "name": "Dockerfile",
        "language": "dockerfile"
    },
    "helm": {
        "extensions": [".yaml", ".yml", ".tpl"],
        "markers": ["{{", ".Values.", ".Release.", "helm.sh/chart"],
        "name": "Helm Chart",
        "language": "yaml"
    }
}


def detect_config_type(filename: str, content: str) -> str:
    """Detect the configuration type from filename and content."""
    filename_lower = filename.lower()

    # Check Dockerfile first (special case)
    if "dockerfile" in filename_lower:
        return "dockerfile"

    # Check by extension
    for config_type, info in CONFIG_TYPES.items():
        for ext in info["extensions"]:
            if filename_lower.endswith(ext):
                # For YAML files, need to check content markers
                if ext in [".yaml", ".yml", ".json", ".template"]:
                    # Check for specific markers
                    for marker in info["markers"]:
                        if marker in content:
                            return config_type
                else:
                    return config_type

    # Check by content markers
    for config_type, info in CONFIG_TYPES.items():
        marker_count = sum(1 for m in info["markers"] if m in content)
        if marker_count >= 2:
            return config_type

    # Default to terraform for .tf files or unknown
    return "terraform"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_api_key(provider: str, header_key: Optional[str] = None) -> str:
    """Get API key from environment or header for specified provider."""
    if provider not in PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown provider: {provider}. Supported: {list(PROVIDERS.keys())}"
        )

    # Priority: Environment variable > Header
    env_key = ENV_API_KEYS.get(provider)
    api_key = env_key or header_key

    if not api_key:
        env_var = PROVIDERS[provider]["env_var"]
        raise HTTPException(
            status_code=401,
            detail=f"API key required for {PROVIDERS[provider]['name']}. Set {env_var} in .env or provide X-API-Key header."
        )

    return api_key


def validate_model(provider: str, model: Optional[str]) -> str:
    """Validate and return the model to use."""
    if not model:
        return PROVIDERS[provider]["default_model"]

    if model not in PROVIDERS[provider]["models"]:
        valid_models = list(PROVIDERS[provider]["models"].keys())
        raise HTTPException(
            status_code=400,
            detail=f"Invalid model '{model}' for {provider}. Valid models: {valid_models}"
        )

    return model


async def call_ai_provider(provider: str, model: str, api_key: str, prompt: str) -> str:
    """Call the appropriate AI provider and return the response text."""

    if provider == "anthropic":
        client = Anthropic(api_key=api_key)
        message = client.messages.create(
            model=model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text

    elif provider == "openai":
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content

    elif provider == "google":
        genai.configure(api_key=api_key)
        model_instance = genai.GenerativeModel(model)
        response = model_instance.generate_content(prompt)
        return response.text

    elif provider == "groq":
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content

    else:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")


# AWS pricing estimates (simplified, us-east-1)
AWS_PRICING = {
    "instance_types": {
        "t2.micro": 8.50, "t2.small": 17.00, "t2.medium": 34.00, "t2.large": 68.00, "t2.xlarge": 136.00, "t2.2xlarge": 272.00,
        "t3.micro": 7.60, "t3.small": 15.20, "t3.medium": 30.40, "t3.large": 60.80, "t3.xlarge": 121.60, "t3.2xlarge": 243.20,
        "m5.large": 70.00, "m5.xlarge": 140.00, "m5.2xlarge": 280.00, "m5.4xlarge": 560.00,
        "r5.large": 91.00, "r5.xlarge": 182.00, "r5.2xlarge": 364.00, "r5.4xlarge": 728.00,
        "c5.large": 62.00, "c5.xlarge": 124.00, "c5.2xlarge": 248.00, "c5.4xlarge": 496.00,
    },
    "rds_instance_types": {
        "db.t3.micro": 12.00, "db.t3.small": 24.00, "db.t3.medium": 48.00, "db.t3.large": 96.00,
        "db.r5.large": 175.00, "db.r5.xlarge": 350.00, "db.r5.2xlarge": 700.00, "db.r5.4xlarge": 1400.00,
        "db.m5.large": 125.00, "db.m5.xlarge": 250.00, "db.m5.2xlarge": 500.00, "db.m5.4xlarge": 1000.00,
    },
    "storage_per_gb": 0.10,
    "s3_per_gb": 0.023,
    "nat_gateway": 32.00,
    "load_balancer": 16.00,
}

# Secret patterns for detection
SECRET_PATTERNS = [
    {"name": "AWS Access Key", "pattern": r'AKIA[0-9A-Z]{16}', "severity": "critical"},
    {"name": "AWS Secret Key", "pattern": r'(?i)(aws_secret_access_key|secret_key)\s*=\s*["\']?[A-Za-z0-9/+=]{40}["\']?', "severity": "critical"},
    {"name": "Generic Password", "pattern": r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "severity": "critical"},
    {"name": "Generic Secret", "pattern": r'(?i)(secret|api_key|apikey|token|auth_token)\s*=\s*["\'][^"\']{8,}["\']', "severity": "critical"},
    {"name": "Private Key", "pattern": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "severity": "critical"},
    {"name": "GitHub Token", "pattern": r'gh[pousr]_[A-Za-z0-9_]{36,}', "severity": "critical"},
    {"name": "Slack Token", "pattern": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', "severity": "critical"},
    {"name": "Generic API Key", "pattern": r'(?i)api[_-]?key\s*=\s*["\'][a-zA-Z0-9]{20,}["\']', "severity": "critical"},
    {"name": "Database Connection String", "pattern": r'(?i)(mysql|postgres|mongodb|redis)://[^"\'\s]+:[^"\'\s]+@', "severity": "critical"},
    {"name": "Hardcoded IP (possible internal)", "pattern": r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', "severity": "warning"},
]


def get_secret_fix_code(secret_name: str, config_type: str) -> str:
    """Get format-specific fix code for secrets."""
    var_name = secret_name.lower().replace(" ", "_")

    fixes = {
        "terraform": f'''# Use variables or secrets manager instead:
variable "{var_name}" {{
  description = "Sensitive value - do not hardcode"
  type        = string
  sensitive   = true
}}''',
        "cloudformation": f'''# Use Parameters or Secrets Manager:
Parameters:
  {var_name.title().replace("_", "")}:
    Type: String
    NoEcho: true
    Description: "Sensitive value - reference from Secrets Manager"

# Or use dynamic reference:
# {{{{resolve:secretsmanager:MySecret:SecretString:{var_name}}}}}''',
        "kubernetes": f'''# Use Secrets instead of hardcoding:
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: Opaque
stringData:
  {var_name}: "<value-from-external-secret-manager>"

# Then reference in pod:
# envFrom:
#   - secretRef:
#       name: my-secret''',
        "dockerfile": f'''# Never hardcode secrets in Dockerfile!
# Use build args (for non-sensitive) or runtime env vars:
ARG {var_name.upper()}
# Better: Use Docker secrets or env vars at runtime
# docker run -e {var_name.upper()}=<value> myimage''',
        "helm": f'''# Use values.yaml and Kubernetes secrets:
# values.yaml:
# secrets:
#   {var_name}: ""  # Set via --set or external secrets

# template:
# {{{{- if .Values.secrets.{var_name} }}}}
#   {var_name}: {{{{ .Values.secrets.{var_name} | b64enc }}}}
# {{{{- end }}}}'''
    }
    return fixes.get(config_type, fixes["terraform"])


def detect_secrets(content: str, config_type: str = "terraform") -> list[dict]:
    """Scan content for hardcoded secrets and sensitive data."""
    found_secrets = []
    lines = content.split('\n')

    for pattern_info in SECRET_PATTERNS:
        pattern = re.compile(pattern_info["pattern"])
        for line_num, line in enumerate(lines, 1):
            matches = pattern.findall(line)
            if matches:
                # Mask the actual secret value
                masked_line = line.strip()
                if len(masked_line) > 80:
                    masked_line = masked_line[:80] + "..."

                found_secrets.append({
                    "id": f"secret-{pattern_info['name'].lower().replace(' ', '-')}-{line_num}",
                    "severity": pattern_info["severity"],
                    "category": "security",
                    "title": f"Hardcoded {pattern_info['name']} Detected",
                    "description": f"Found potential {pattern_info['name']} on line {line_num}. Hardcoded secrets in infrastructure code pose severe security risks. Use environment variables or a secrets manager instead.",
                    "resource": None,
                    "line_hint": line_num,
                    "fix_code": get_secret_fix_code(pattern_info['name'], config_type)
                })

    return found_secrets


REVIEW_PROMPTS = {
    "terraform": """You are a senior cloud architect. Analyze this Terraform configuration and return a JSON response.

IMPORTANT: Return ONLY valid JSON, no markdown or explanation outside the JSON.

{{
  "summary": "2-3 sentence overview of the configuration and main concerns",
  "overall_score": <number 0-100, where 100 is perfect>,
  "issues": [
    {{
      "id": "unique-id",
      "severity": "critical" | "warning" | "info",
      "category": "security" | "cost" | "reliability" | "best-practice",
      "title": "Short title of the issue",
      "description": "Detailed explanation of what's wrong and why it matters",
      "resource": "resource name (e.g., aws_instance.web)",
      "line_hint": "line number or range if identifiable, otherwise null",
      "fix_code": "The corrected code snippet that fixes this issue"
    }}
  ],
  "positives": ["List of things done well in this configuration"],
  "resource_inventory": [
    {{
      "type": "aws_instance | aws_db_instance | aws_s3_bucket | etc",
      "name": "resource name",
      "details": "instance type, size, or other cost-relevant info"
    }}
  ]
}}

Focus on: Open security groups, missing encryption, exposed secrets, overly permissive IAM, public access, oversized instances, single points of failure, missing backups, hardcoded values, missing tags.

TERRAFORM CONFIG:
```hcl
{content}
```""",

    "cloudformation": """You are a senior AWS cloud architect. Analyze this CloudFormation template and return a JSON response.

IMPORTANT: Return ONLY valid JSON, no markdown or explanation outside the JSON.

{{
  "summary": "2-3 sentence overview of the template and main concerns",
  "overall_score": <number 0-100, where 100 is perfect>,
  "issues": [
    {{
      "id": "unique-id",
      "severity": "critical" | "warning" | "info",
      "category": "security" | "cost" | "reliability" | "best-practice",
      "title": "Short title of the issue",
      "description": "Detailed explanation of what's wrong and why it matters",
      "resource": "logical resource name",
      "line_hint": "line number or range if identifiable, otherwise null",
      "fix_code": "The corrected YAML/JSON snippet that fixes this issue"
    }}
  ],
  "positives": ["List of things done well"],
  "resource_inventory": [
    {{
      "type": "AWS::EC2::Instance | AWS::RDS::DBInstance | AWS::S3::Bucket | etc",
      "name": "logical resource name",
      "details": "instance type, size, or other cost-relevant info"
    }}
  ]
}}

Focus on: Security group rules, IAM policies, encryption settings, public access, DeletionPolicy, UpdateReplacePolicy, missing Metadata, Parameter constraints, hardcoded values.

CLOUDFORMATION TEMPLATE:
```yaml
{content}
```""",

    "kubernetes": """You are a senior Kubernetes security engineer. Analyze this Kubernetes manifest and return a JSON response.

IMPORTANT: Return ONLY valid JSON, no markdown or explanation outside the JSON.

{{
  "summary": "2-3 sentence overview of the manifest and main concerns",
  "overall_score": <number 0-100, where 100 is perfect>,
  "issues": [
    {{
      "id": "unique-id",
      "severity": "critical" | "warning" | "info",
      "category": "security" | "cost" | "reliability" | "best-practice",
      "title": "Short title of the issue",
      "description": "Detailed explanation of what's wrong and why it matters",
      "resource": "resource kind/name",
      "line_hint": "line number or range if identifiable, otherwise null",
      "fix_code": "The corrected YAML snippet that fixes this issue"
    }}
  ],
  "positives": ["List of things done well"],
  "resource_inventory": [
    {{
      "type": "Deployment | Service | Pod | ConfigMap | etc",
      "name": "resource name",
      "details": "replicas, image, resource limits"
    }}
  ]
}}

Focus on: Running as root, privileged containers, missing resource limits/requests, hostNetwork/hostPID, missing securityContext, latest image tags, missing readiness/liveness probes, secrets in env vars, missing network policies.

KUBERNETES MANIFEST:
```yaml
{content}
```""",

    "dockerfile": """You are a senior container security engineer. Analyze this Dockerfile and return a JSON response.

IMPORTANT: Return ONLY valid JSON, no markdown or explanation outside the JSON.

{{
  "summary": "2-3 sentence overview of the Dockerfile and main concerns",
  "overall_score": <number 0-100, where 100 is perfect>,
  "issues": [
    {{
      "id": "unique-id",
      "severity": "critical" | "warning" | "info",
      "category": "security" | "cost" | "reliability" | "best-practice",
      "title": "Short title of the issue",
      "description": "Detailed explanation of what's wrong and why it matters",
      "resource": "instruction or stage",
      "line_hint": "line number or range if identifiable, otherwise null",
      "fix_code": "The corrected Dockerfile instruction(s)"
    }}
  ],
  "positives": ["List of things done well"],
  "resource_inventory": [
    {{
      "type": "base_image | stage | layer",
      "name": "image or stage name",
      "details": "tag, size considerations"
    }}
  ]
}}

Focus on: Running as root, using latest tags, hardcoded secrets/passwords, unnecessary packages, missing USER instruction, ADD vs COPY, large base images, missing .dockerignore recommendations, multi-stage builds, layer optimization.

DOCKERFILE:
```dockerfile
{content}
```""",

    "helm": """You are a senior Kubernetes/Helm engineer. Analyze this Helm chart template and return a JSON response.

IMPORTANT: Return ONLY valid JSON, no markdown or explanation outside the JSON.

{{
  "summary": "2-3 sentence overview of the chart and main concerns",
  "overall_score": <number 0-100, where 100 is perfect>,
  "issues": [
    {{
      "id": "unique-id",
      "severity": "critical" | "warning" | "info",
      "category": "security" | "cost" | "reliability" | "best-practice",
      "title": "Short title of the issue",
      "description": "Detailed explanation of what's wrong and why it matters",
      "resource": "template or value reference",
      "line_hint": "line number or range if identifiable, otherwise null",
      "fix_code": "The corrected template snippet"
    }}
  ],
  "positives": ["List of things done well"],
  "resource_inventory": [
    {{
      "type": "Deployment | Service | ConfigMap | etc",
      "name": "resource name",
      "details": "relevant values"
    }}
  ]
}}

Focus on: Hardcoded values that should be in values.yaml, missing default values, security contexts, resource limits, missing required values validation, image tag handling, secrets management.

HELM TEMPLATE:
```yaml
{content}
```"""
}


class Issue(BaseModel):
    id: str
    severity: str
    category: str
    title: str
    description: str
    resource: Optional[str] = None
    line_hint: Optional[Union[str, int]] = None
    fix_code: Optional[str] = None


class ResourceInventory(BaseModel):
    type: str
    name: str
    details: Optional[str] = None


class CostEstimate(BaseModel):
    monthly_total: float
    breakdown: dict
    notes: list[str]


class StructuredReview(BaseModel):
    summary: str
    overall_score: int
    issues: list[Issue]
    positives: list[str]
    resource_inventory: list[ResourceInventory]
    cost_estimate: Optional[CostEstimate] = None


class RedactedItem(BaseModel):
    original: str
    replacement: str
    category: str

class PrivacyReport(BaseModel):
    enabled: bool = False
    items_redacted: int = 0
    categories: dict = {}
    redactions: list[RedactedItem] = []

class ReviewResponse(BaseModel):
    review: StructuredReview
    filename: str
    lines_analyzed: int
    config_type: str = "terraform"
    privacy: Optional[PrivacyReport] = None


def estimate_costs(terraform_content: str, resource_inventory: list) -> CostEstimate:
    """Estimate monthly AWS costs based on Terraform resources."""
    breakdown = {}
    notes = []

    for resource in resource_inventory:
        rtype = resource.get("type", "")
        details = resource.get("details", "") or ""
        name = resource.get("name", "")

        if rtype == "aws_instance":
            # Extract instance type
            instance_type = None
            for itype in AWS_PRICING["instance_types"]:
                if itype in details.lower():
                    instance_type = itype
                    break
            if instance_type:
                cost = AWS_PRICING["instance_types"][instance_type]
                breakdown[f"EC2: {name}"] = cost
            else:
                breakdown[f"EC2: {name}"] = 50.00
                notes.append(f"Unknown instance type for {name}, estimated $50/mo")

        elif rtype == "aws_db_instance":
            instance_class = None
            for iclass in AWS_PRICING["rds_instance_types"]:
                if iclass in details.lower():
                    instance_class = iclass
                    break
            if instance_class:
                cost = AWS_PRICING["rds_instance_types"][instance_class]
                breakdown[f"RDS: {name}"] = cost
            else:
                breakdown[f"RDS: {name}"] = 100.00
                notes.append(f"Unknown RDS class for {name}, estimated $100/mo")

            # Add storage estimate
            storage_match = re.search(r'(\d+)\s*(?:gb|GB)', details)
            if storage_match:
                storage_gb = int(storage_match.group(1))
                breakdown[f"RDS Storage: {name}"] = storage_gb * AWS_PRICING["storage_per_gb"]

        elif rtype == "aws_s3_bucket":
            breakdown[f"S3: {name}"] = 5.00
            notes.append(f"S3 bucket {name} estimated at $5/mo (depends on usage)")

        elif rtype == "aws_nat_gateway":
            breakdown[f"NAT Gateway: {name}"] = AWS_PRICING["nat_gateway"]

        elif rtype in ["aws_lb", "aws_alb", "aws_elb"]:
            breakdown[f"Load Balancer: {name}"] = AWS_PRICING["load_balancer"]

    monthly_total = sum(breakdown.values())

    if not breakdown:
        notes.append("No recognizable AWS resources found for cost estimation")

    return CostEstimate(
        monthly_total=round(monthly_total, 2),
        breakdown=breakdown,
        notes=notes
    )


def parse_review_response(response_text: str) -> dict:
    """Parse the JSON response from Claude, handling potential formatting issues."""
    # Try to extract JSON from the response
    text = response_text.strip()

    # If wrapped in code blocks, extract
    if "```json" in text:
        match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if match:
            text = match.group(1)
    elif "```" in text:
        match = re.search(r'```\s*(.*?)\s*```', text, re.DOTALL)
        if match:
            text = match.group(1)

    # Try to find JSON object
    if not text.startswith('{'):
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            text = match.group(0)

    return json.loads(text)


async def analyze_config(
    content: str,
    filename: str,
    api_key: str,
    provider: str = "anthropic",
    model: str = None,
    config_type: str = None,
    anonymize: bool = False
) -> ReviewResponse:
    """Core analysis function for all config types."""

    if len(content) > 100000:
        raise HTTPException(
            status_code=400,
            detail="Content too large. Please send under 100KB."
        )

    # Auto-detect config type if not specified
    if not config_type:
        config_type = detect_config_type(filename, content)

    # Validate and get model
    model = validate_model(provider, model)

    # Always detect secrets on ORIGINAL content (local regex, no AI needed)
    secret_issues = detect_secrets(content, config_type)

    # Privacy Mode: anonymize content before sending to AI
    anon_mapping = None
    privacy_report = None
    ai_content = content
    if anonymize:
        anonymizer = ContentAnonymizer()
        ai_content, anon_mapping = anonymizer.anonymize(content)

        # Build privacy report from mapping
        categories = {}
        redactions = []
        for pseudonym, original in anon_mapping.items():
            if pseudonym.startswith('REDACTED_SECRET_'):
                cat = 'secret'
                # Mask the middle of the secret for the report
                if len(original) > 8:
                    display = original[:4] + '*' * (len(original) - 8) + original[-4:]
                else:
                    display = '*' * len(original)
            elif pseudonym.startswith('10.') or pseudonym.startswith('172.') or pseudonym.startswith('192.'):
                cat = 'ip'
                display = original
            elif pseudonym.startswith('arn:'):
                cat = 'arn'
                display = original
            elif pseudonym.startswith('redacted-host-'):
                cat = 'domain'
                display = original
            elif '@redacted-domain' in pseudonym:
                cat = 'email'
                display = original
            elif pseudonym.startswith('redacted-bucket-'):
                cat = 'bucket'
                display = original
            elif pseudonym.startswith('100'):
                cat = 'account_id'
                display = original
            else:
                cat = 'other'
                display = original

            categories[cat] = categories.get(cat, 0) + 1
            redactions.append(RedactedItem(
                original=display,
                replacement=pseudonym,
                category=cat
            ))

        privacy_report = PrivacyReport(
            enabled=True,
            items_redacted=len(anon_mapping),
            categories=categories,
            redactions=redactions
        )

        # Log what was anonymized
        print(f"\n{'='*60}")
        print(f"PRIVACY MODE: {len(anon_mapping)} items redacted")
        for pseudo, original in anon_mapping.items():
            print(f"  {original} -> {pseudo}")
        print(f"{'='*60}")
        print(f"\nContent sent to AI:\n{ai_content[:500]}...")
        print(f"{'='*60}\n")

    # Get the appropriate prompt
    prompt_template = REVIEW_PROMPTS.get(config_type, REVIEW_PROMPTS["terraform"])
    prompt = prompt_template.format(content=ai_content)

    try:
        # Call the AI provider with (possibly anonymized) content
        response_text = await call_ai_provider(provider, model, api_key, prompt)
        review_data = parse_review_response(response_text)

        # Privacy Mode: de-anonymize AI results back to original values
        if anon_mapping:
            review_data = anonymizer.deanonymize_results(review_data, anon_mapping)

        # Calculate cost estimate (only for AWS resources) - use original content
        cost_estimate = None
        if config_type in ["terraform", "cloudformation"]:
            cost_estimate = estimate_costs(
                content,
                review_data.get("resource_inventory", [])
            )

        # Combine AI issues with detected secrets (secrets first - they're critical)
        all_issues = secret_issues + review_data.get("issues", [])

        # Adjust score if secrets were found (major penalty)
        base_score = review_data.get("overall_score", 50)
        secret_penalty = len([s for s in secret_issues if s["severity"] == "critical"]) * 15
        adjusted_score = max(0, base_score - secret_penalty)

        # Build structured review
        structured_review = StructuredReview(
            summary=review_data.get("summary", "Analysis complete"),
            overall_score=adjusted_score,
            issues=[Issue(**issue) for issue in all_issues],
            positives=review_data.get("positives", []),
            resource_inventory=[ResourceInventory(**r) for r in review_data.get("resource_inventory", [])],
            cost_estimate=cost_estimate
        )

        return ReviewResponse(
            review=structured_review,
            filename=filename,
            lines_analyzed=len(content.splitlines()),
            config_type=config_type,
            privacy=privacy_report
        )

    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse analysis response: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


SUPPORTED_EXTENSIONS = ['.tf', '.tf.json', '.yaml', '.yml', '.json', '.template', '.tpl', '.dockerfile']


@app.get("/")
async def root():
    """Return API status and available providers/models."""
    # Build provider info for frontend
    providers_info = {}
    for provider_id, config in PROVIDERS.items():
        providers_info[provider_id] = {
            "name": config["name"],
            "models": {
                model_id: model_info
                for model_id, model_info in config["models"].items()
            },
            "default_model": config["default_model"],
            "configured": provider_id in ENV_API_KEYS  # True if env var is set
        }

    return {
        "status": "healthy",
        "service": "Cloud Architecture Review Agent",
        "supported_formats": list(CONFIG_TYPES.keys()),
        "providers": providers_info,
        # Legacy field for backwards compatibility
        "api_key_configured": bool(ENV_API_KEYS)
    }


@app.post("/review", response_model=ReviewResponse)
async def review_config(
    file: UploadFile = File(...),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_provider: Optional[str] = Header("anthropic", alias="X-Provider"),
    x_model: Optional[str] = Header(None, alias="X-Model"),
    x_anonymize: Optional[str] = Header("false", alias="X-Anonymize")
):
    """Upload a configuration file and get a structured security review.

    Headers:
    - X-API-Key: Your API key (optional if env var is set for the provider)
    - X-Provider: AI provider to use (anthropic, openai, google, groq). Default: anthropic
    - X-Model: Model to use (optional, uses provider's default)
    - X-Anonymize: Enable privacy mode to redact sensitive data before AI analysis (true/false)

    Supported formats: Terraform, CloudFormation, Kubernetes, Dockerfile, Helm
    """
    filename = file.filename.lower()

    # Check for supported file types
    is_supported = (
        any(filename.endswith(ext) for ext in SUPPORTED_EXTENSIONS) or
        "dockerfile" in filename
    )

    if not is_supported:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type. Supported: Terraform (.tf), CloudFormation (.yaml/.json), Kubernetes (.yaml), Dockerfile, Helm (.yaml/.tpl)"
        )

    api_key = get_api_key(x_provider, x_api_key)
    content = await file.read()
    file_content = content.decode('utf-8')
    anonymize = x_anonymize.lower() == "true"

    return await analyze_config(file_content, file.filename, api_key, x_provider, x_model, anonymize=anonymize)


@app.post("/review/text", response_model=ReviewResponse)
async def review_config_text(
    content: str,
    config_type: str = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_provider: Optional[str] = Header("anthropic", alias="X-Provider"),
    x_model: Optional[str] = Header(None, alias="X-Model"),
    x_anonymize: Optional[str] = Header("false", alias="X-Anonymize")
):
    """Review configuration content passed as text.

    Headers:
    - X-API-Key: Your API key (optional if env var is set for the provider)
    - X-Provider: AI provider to use (anthropic, openai, google, groq). Default: anthropic
    - X-Model: Model to use (optional, uses provider's default)
    - X-Anonymize: Enable privacy mode to redact sensitive data before AI analysis (true/false)

    Optionally specify config_type: terraform, cloudformation, kubernetes, dockerfile, helm
    """
    filename = "pasted_config"
    if config_type:
        ext_map = {"terraform": ".tf", "cloudformation": ".yaml", "kubernetes": ".yaml", "dockerfile": "", "helm": ".yaml"}
        filename += ext_map.get(config_type, ".tf")
    else:
        filename += ".tf"

    anonymize = x_anonymize.lower() == "true"
    api_key = get_api_key(x_provider, x_api_key)
    return await analyze_config(content, filename, api_key, x_provider, x_model, config_type, anonymize=anonymize)


@app.post("/review/pdf")
async def generate_pdf_report(
    file: UploadFile = File(...),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_provider: Optional[str] = Header("anthropic", alias="X-Provider"),
    x_model: Optional[str] = Header(None, alias="X-Model"),
    x_anonymize: Optional[str] = Header("false", alias="X-Anonymize")
):
    """Generate a PDF report from a configuration file.

    Headers:
    - X-API-Key: Your API key (optional if env var is set for the provider)
    - X-Provider: AI provider to use (anthropic, openai, google, groq). Default: anthropic
    - X-Model: Model to use (optional, uses provider's default)
    - X-Anonymize: Enable privacy mode to redact sensitive data before AI analysis (true/false)
    """
    filename = file.filename.lower()

    is_supported = (
        any(filename.endswith(ext) for ext in SUPPORTED_EXTENSIONS) or
        "dockerfile" in filename
    )

    if not is_supported:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type for PDF generation"
        )

    api_key = get_api_key(x_provider, x_api_key)
    content = await file.read()
    file_content = content.decode('utf-8')
    anonymize = x_anonymize.lower() == "true"

    # Get the review
    review_response = await analyze_config(file_content, file.filename, api_key, x_provider, x_model, anonymize=anonymize)
    review = review_response.review
    config_type = review_response.config_type

    # Generate HTML for PDF
    html_content = generate_report_html(review, file.filename, config_type)

    # Convert to PDF using WeasyPrint
    try:
        from weasyprint import HTML
        pdf_bytes = HTML(string=html_content).write_pdf()

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="terraform-review-{file.filename}.pdf"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


def generate_report_html(review: StructuredReview, filename: str, config_type: str = "terraform") -> str:
    """Generate HTML for PDF report."""
    config_name = CONFIG_TYPES.get(config_type, {}).get("name", "Configuration")

    # Count issues by severity
    critical_count = len([i for i in review.issues if i.severity == "critical"])
    warning_count = len([i for i in review.issues if i.severity == "warning"])
    info_count = len([i for i in review.issues if i.severity == "info"])

    issues_html = ""
    for issue in review.issues:
        severity_color = {"critical": "#ef4444", "warning": "#f59e0b", "info": "#3b82f6"}[issue.severity]
        severity_bg = {"critical": "#fef2f2", "warning": "#fffbeb", "info": "#eff6ff"}[issue.severity]

        fix_html = ""
        if issue.fix_code:
            fix_html = f'''
            <div class="fix-box">
                <strong style="font-size: 8pt;">Recommended Fix:</strong>
                <pre>{issue.fix_code}</pre>
            </div>
            '''

        issues_html += f'''
        <div class="issue {issue.severity}">
            <div class="issue-header">
                <span class="issue-title">{issue.title}</span>
                <span class="badge {issue.severity}">{issue.severity}</span>
            </div>
            <p>{issue.description}</p>
            {f'<p style="font-size: 9pt; color: #64748b;">Resource: <code>{issue.resource}</code></p>' if issue.resource else ''}
            {fix_html}
        </div>
        '''

    positives_html = "".join([f'<li style="margin-bottom: 8px; color: #166534;">{p}</li>' for p in review.positives])

    cost_html = ""
    if review.cost_estimate:
        breakdown_html = "".join([
            f'<tr><td>{k}</td><td style="text-align: right;">${v:.2f}</td></tr>'
            for k, v in review.cost_estimate.breakdown.items()
        ])
        cost_html = f'''
        <h2>Cost Estimate</h2>
        <div class="cost-box">
            <div class="cost-total">${review.cost_estimate.monthly_total:.2f}/month</div>
            <div style="color: #15803d; font-size: 9pt;">Estimated AWS costs</div>
        </div>
        <table>
            <thead>
                <tr><th>Resource</th><th style="text-align: right;">Monthly Cost</th></tr>
            </thead>
            <tbody>{breakdown_html}</tbody>
        </table>
        '''

    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            @page {{ size: A4; margin: 1.5cm; }}
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 10pt; line-height: 1.4; color: #1e293b; }}
            h1 {{ font-size: 16pt; margin: 0 0 4px 0; }}
            h2 {{ font-size: 12pt; margin: 16px 0 8px 0; padding-bottom: 4px; border-bottom: 1px solid #e2e8f0; }}
            h3 {{ font-size: 11pt; margin: 0 0 4px 0; }}
            p {{ margin: 0 0 8px 0; }}
            code {{ background: #f1f5f9; padding: 1px 4px; border-radius: 3px; font-size: 9pt; }}
            pre {{ white-space: pre-wrap; word-wrap: break-word; font-size: 8pt; margin: 4px 0; }}
            .header {{ text-align: center; margin-bottom: 20px; }}
            .subtitle {{ color: #64748b; font-size: 9pt; }}
            .score-grid {{ display: flex; gap: 8px; margin-bottom: 16px; }}
            .score-card {{ flex: 1; padding: 10px; border-radius: 6px; text-align: center; }}
            .score-card.main {{ background: linear-gradient(135deg, #3b82f6, #8b5cf6); color: white; }}
            .score-card.critical {{ background: #fef2f2; }}
            .score-card.warning {{ background: #fffbeb; }}
            .score-card.info {{ background: #eff6ff; }}
            .score-value {{ font-size: 18pt; font-weight: 700; line-height: 1; }}
            .score-label {{ font-size: 8pt; margin-top: 2px; }}
            .summary-box {{ background: #f8fafc; padding: 10px; border-radius: 6px; margin-bottom: 16px; }}
            .issue {{ padding: 10px; margin-bottom: 8px; border-radius: 4px; page-break-inside: avoid; }}
            .issue.critical {{ background: #fef2f2; border-left: 3px solid #ef4444; }}
            .issue.warning {{ background: #fffbeb; border-left: 3px solid #f59e0b; }}
            .issue.info {{ background: #eff6ff; border-left: 3px solid #3b82f6; }}
            .issue-header {{ display: flex; justify-content: space-between; margin-bottom: 4px; }}
            .issue-title {{ font-weight: 600; font-size: 10pt; }}
            .badge {{ padding: 2px 6px; border-radius: 3px; font-size: 7pt; font-weight: 600; text-transform: uppercase; color: white; }}
            .badge.critical {{ background: #ef4444; }}
            .badge.warning {{ background: #f59e0b; color: #1e293b; }}
            .badge.info {{ background: #3b82f6; }}
            .fix-box {{ background: #1e293b; color: #e2e8f0; padding: 8px; border-radius: 4px; margin-top: 6px; }}
            .cost-box {{ background: #f0fdf4; border: 1px solid #86efac; border-radius: 6px; padding: 10px; margin: 16px 0; }}
            .cost-total {{ font-size: 14pt; font-weight: 700; color: #166534; }}
            table {{ width: 100%; border-collapse: collapse; font-size: 9pt; }}
            th, td {{ padding: 6px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
            th {{ background: #f8fafc; }}
            ul {{ padding-left: 16px; margin: 0; }}
            li {{ margin-bottom: 4px; }}
            .footer {{ margin-top: 24px; padding-top: 12px; border-top: 1px solid #e2e8f0; text-align: center; font-size: 8pt; color: #94a3b8; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>{config_name} Security Review</h1>
            <p class="subtitle">Generated by TerraGuard</p>
            <p class="subtitle">File: {filename}</p>
        </div>

        <div class="score-grid">
            <div class="score-card main">
                <div class="score-value">{review.overall_score}</div>
                <div class="score-label">Score</div>
            </div>
            <div class="score-card critical">
                <div class="score-value" style="color: #ef4444;">{critical_count}</div>
                <div class="score-label" style="color: #991b1b;">Critical</div>
            </div>
            <div class="score-card warning">
                <div class="score-value" style="color: #f59e0b;">{warning_count}</div>
                <div class="score-label" style="color: #92400e;">Warnings</div>
            </div>
            <div class="score-card info">
                <div class="score-value" style="color: #3b82f6;">{info_count}</div>
                <div class="score-label" style="color: #1e40af;">Info</div>
            </div>
        </div>

        <div class="summary-box">
            <h3>Summary</h3>
            <p>{review.summary}</p>
        </div>

        <h2>Issues Found</h2>
        {issues_html if issues_html else '<p style="color: #64748b;">No issues found. Great job!</p>'}

        <h2>What's Done Well</h2>
        <ul>{positives_html if positives_html else '<li style="color: #64748b;">No specific positives identified.</li>'}</ul>

        {cost_html}

        <div class="footer">
            <p>Generated by Cloud Architecture Review Agent</p>
        </div>
    </body>
    </html>
    '''


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
