"""
Cloud Architecture Review Agent - Backend API
"""
import os
import json
import re
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional, Union
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Cloud Architecture Review Agent")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

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


def detect_secrets(content: str) -> list[dict]:
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
                    "description": f"Found potential {pattern_info['name']} on line {line_num}. Hardcoded secrets in infrastructure code pose severe security risks. Use environment variables, AWS Secrets Manager, or HashiCorp Vault instead.",
                    "resource": None,
                    "line_hint": line_num,
                    "fix_code": f'# Use variables or secrets manager instead:\nvariable "{pattern_info["name"].lower().replace(" ", "_")}" {{\n  description = "Sensitive value - do not hardcode"\n  type        = string\n  sensitive   = true\n}}'
                })

    return found_secrets


REVIEW_PROMPT = """You are a senior cloud architect. Analyze this Terraform configuration and return a JSON response.

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
      "resource": "resource name from terraform (e.g., aws_instance.web)",
      "line_hint": "line number or range if identifiable, otherwise null",
      "fix_code": "The corrected Terraform code snippet that fixes this issue"
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

Categories:
- security: Open ports, missing encryption, exposed secrets, overly permissive IAM, public access
- cost: Oversized instances, missing spot/reserved options, unnecessary resources
- reliability: Single points of failure, no backups, no multi-AZ, missing health checks
- best-practice: Hardcoded values, missing tags, poor naming, no modules

Severity levels:
- critical: Security vulnerabilities, data exposure risks, compliance violations
- warning: Important issues that should be addressed but aren't immediate risks
- info: Suggestions and improvements for better practices

For each issue, ALWAYS provide fix_code with the corrected Terraform snippet.

TERRAFORM CONFIG:
```hcl
{terraform_content}
```"""


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


class ReviewResponse(BaseModel):
    review: StructuredReview
    filename: str
    lines_analyzed: int


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


async def analyze_terraform(terraform_content: str, filename: str) -> ReviewResponse:
    """Core analysis function used by both endpoints."""

    if len(terraform_content) > 100000:
        raise HTTPException(
            status_code=400,
            detail="Content too large. Please send under 100KB."
        )

    prompt = REVIEW_PROMPT.format(terraform_content=terraform_content)

    try:
        message = client.messages.create(
            model="claude-sonnet-4-20250514",  # Balanced speed + quality
            max_tokens=4096,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        response_text = message.content[0].text
        review_data = parse_review_response(response_text)

        # Detect hardcoded secrets
        secret_issues = detect_secrets(terraform_content)

        # Calculate cost estimate
        cost_estimate = estimate_costs(
            terraform_content,
            review_data.get("resource_inventory", [])
        )

        # Combine Claude's issues with detected secrets (secrets first - they're critical)
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
            lines_analyzed=len(terraform_content.splitlines())
        )

    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse analysis response: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/")
async def root():
    return {"status": "healthy", "service": "Cloud Architecture Review Agent"}


@app.post("/review", response_model=ReviewResponse)
async def review_terraform(file: UploadFile = File(...)):
    """Upload a Terraform file and get a structured architecture review."""

    if not file.filename.endswith(('.tf', '.tf.json')):
        raise HTTPException(
            status_code=400,
            detail="Please upload a Terraform file (.tf or .tf.json)"
        )

    content = await file.read()
    terraform_content = content.decode('utf-8')

    return await analyze_terraform(terraform_content, file.filename)


@app.post("/review/text", response_model=ReviewResponse)
async def review_terraform_text(terraform_content: str):
    """Review Terraform content passed as text."""
    return await analyze_terraform(terraform_content, "pasted_config.tf")


@app.post("/review/pdf")
async def generate_pdf_report(file: UploadFile = File(...)):
    """Generate a PDF report from a Terraform file."""

    if not file.filename.endswith(('.tf', '.tf.json')):
        raise HTTPException(
            status_code=400,
            detail="Please upload a Terraform file (.tf or .tf.json)"
        )

    content = await file.read()
    terraform_content = content.decode('utf-8')

    # Get the review
    review_response = await analyze_terraform(terraform_content, file.filename)
    review = review_response.review

    # Generate HTML for PDF
    html_content = generate_report_html(review, file.filename)

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


def generate_report_html(review: StructuredReview, filename: str) -> str:
    """Generate HTML for PDF report."""

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
            <h1>Terraform Security Review</h1>
            <p class="subtitle">Generated by Cloud Architecture Review Agent</p>
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
