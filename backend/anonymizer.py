"""
Content anonymizer for TerraGuard Privacy Mode.

Redacts sensitive infrastructure data (IPs, account IDs, domains, secrets)
before sending to AI providers. Generates structurally valid pseudonyms
so AI analysis remains accurate.
"""

import re
from typing import Tuple


# IPs that are meaningful for security analysis and should NOT be anonymized
SKIP_IPS = {'0.0.0.0', '127.0.0.1', '255.255.255.255', '::1', '::'}


class ContentAnonymizer:
    """Anonymizes infrastructure config content with reversible pseudonyms."""

    def __init__(self):
        self._mapping = {}        # original -> pseudonym
        self._reverse = {}        # pseudonym -> original
        self._counters = {
            'ip': 1,
            'domain': 1,
            'email': 1,
            'account': 1,
            'bucket': 1,
            'secret': 1,
            'arn': 1,
        }

        # Patterns ordered from most specific to least specific
        self._patterns = [
            # Connection strings (must come before generic patterns)
            (re.compile(
                r'(mysql|postgres|postgresql|mongodb|redis|amqp)://'
                r'[^\s"\'`\]}>)]+',
                re.IGNORECASE
            ), self._anonymize_connection_string),

            # ARNs
            (re.compile(
                r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s"\'`\]}>),$]+'
            ), self._anonymize_arn),

            # AWS Account IDs (12 digits, typically in quotes or after colons)
            (re.compile(
                r'(?<=[:"/])\d{12}(?=[:/"\s])'
            ), self._anonymize_account_id),

            # Secret/password values - specific known formats
            (re.compile(
                r'(?<=["\'])(?:'
                r'(?:AKIA[0-9A-Z]{16})'                       # AWS access key
                r'|(?:sk-ant-[a-zA-Z0-9\-_]{20,})'            # Anthropic key
                r'|(?:sk-[a-zA-Z0-9\-_]{20,})'                # OpenAI key
                r'|(?:AIza[a-zA-Z0-9\-_]{20,})'               # Google key
                r'|(?:gsk_[a-zA-Z0-9]{20,})'                  # Groq key
                r'|(?:gh[pousr]_[A-Za-z0-9_]{36,})'           # GitHub token
                r'|(?:xox[baprs]-[0-9\-a-zA-Z]{20,})'         # Slack token
                r'|(?:-----BEGIN[A-Z ]+KEY-----[\s\S]*?-----END[A-Z ]+KEY-----)' # Private keys
                r')(?=["\'])',
            ), self._anonymize_secret),

            # Generic secret values: password/secret/token/key = "value"
            (re.compile(
                r'((?:password|passwd|pwd|secret|api_key|apikey|token|auth_token|'
                r'access_key|secret_key|private_key|client_secret|db_password|'
                r'master_password|admin_password)'
                r'\s*[=:]\s*["\'])'
                r'([^"\']{4,})'
                r'(?=["\'])',
                re.IGNORECASE
            ), self._anonymize_secret_value),

            # Email addresses
            (re.compile(
                r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
            ), self._anonymize_email),

            # IP addresses with optional CIDR
            (re.compile(
                r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
                r'(?:/\d{1,2})?\b'
            ), self._anonymize_ip),

            # S3 bucket names in ARN-like or URL-like patterns
            (re.compile(
                r'(?<=(?:s3://|s3:::))[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]'
            ), self._anonymize_bucket),

            # Domain names (but not common ones like amazonaws.com)
            (re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
                r'+(?:com|org|net|io|dev|co|app|cloud|internal|local|corp)\b'
            ), self._anonymize_domain),
        ]

        # Domains to never anonymize (cloud provider domains)
        self._skip_domains = {
            'amazonaws.com', 'aws.amazon.com', 'azure.com',
            'googleapis.com', 'google.com', 'cloudflare.com',
            'terraform.io', 'hashicorp.com', 'github.com',
            'docker.io', 'docker.com', 'gcr.io', 'ghcr.io',
            'example.com', 'example.org', 'example.net',
        }

    def anonymize(self, content: str) -> Tuple[str, dict]:
        """
        Anonymize sensitive data in content.

        Returns:
            (anonymized_content, mapping) where mapping is {pseudonym: original}
        """
        result = content

        for pattern, handler in self._patterns:
            result = pattern.sub(lambda m: handler(m), result)

        return result, dict(self._reverse)

    def deanonymize_text(self, text: str, mapping: dict) -> str:
        """Replace pseudonyms back to original values in a string."""
        if not text or not mapping:
            return text

        result = text
        # Sort by length descending to avoid partial replacements
        for pseudonym, original in sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True):
            result = result.replace(pseudonym, original)
        return result

    def deanonymize_results(self, data, mapping: dict):
        """Recursively walk a dict/list and deanonymize all string values."""
        if not mapping:
            return data

        if isinstance(data, str):
            return self.deanonymize_text(data, mapping)
        elif isinstance(data, dict):
            return {k: self.deanonymize_results(v, mapping) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.deanonymize_results(item, mapping) for item in data]
        return data

    # --- Pseudonym generators ---

    def _get_or_create(self, original: str, category: str, generator) -> str:
        """Get existing pseudonym or create a new one."""
        if original in self._mapping:
            return self._mapping[original]

        pseudonym = generator(self._counters[category])
        self._counters[category] += 1
        self._mapping[original] = pseudonym
        self._reverse[pseudonym] = original
        return pseudonym

    def _anonymize_ip(self, match: re.Match) -> str:
        original = match.group(0)
        # Split off CIDR suffix
        if '/' in original:
            ip, cidr = original.rsplit('/', 1)
            if ip in SKIP_IPS:
                return original
            pseudo_ip = self._get_or_create(ip, 'ip',
                lambda n: f"10.{(n // 256) % 256}.{n % 256}.{(n * 7) % 254 + 1}")
            return f"{pseudo_ip}/{cidr}"
        if original in SKIP_IPS:
            return original
        return self._get_or_create(original, 'ip',
            lambda n: f"10.{(n // 256) % 256}.{n % 256}.{(n * 7) % 254 + 1}")

    def _anonymize_domain(self, match: re.Match) -> str:
        original = match.group(0)
        # Don't anonymize cloud provider domains
        for skip in self._skip_domains:
            if original.endswith(skip) or original == skip:
                return original
        return self._get_or_create(original, 'domain',
            lambda n: f"redacted-host-{n}.example.com")

    def _anonymize_email(self, match: re.Match) -> str:
        original = match.group(0)
        return self._get_or_create(original, 'email',
            lambda n: f"user-{n}@redacted-domain.com")

    def _anonymize_account_id(self, match: re.Match) -> str:
        original = match.group(0)
        return self._get_or_create(original, 'account',
            lambda n: f"{100000000000 + n}")

    def _anonymize_arn(self, match: re.Match) -> str:
        original = match.group(0)
        # Keep the service and structure, replace account + resource name
        parts = original.split(':')
        if len(parts) >= 6:
            service = parts[2]
            region = parts[3]
            resource = parts[5] if len(parts) > 5 else 'resource'
            # Keep resource type prefix (e.g., "role/", "bucket/")
            resource_type = ""
            if '/' in resource:
                resource_type = resource.split('/')[0] + '/'

            n = self._counters['arn']
            pseudo = f"arn:aws:{service}:{region}:{100000000000 + n}:{resource_type}redacted-{n}"
            self._counters['arn'] += 1
            self._mapping[original] = pseudo
            self._reverse[pseudo] = original
            return pseudo
        return original

    def _anonymize_secret(self, match: re.Match) -> str:
        original = match.group(0)
        return self._get_or_create(original, 'secret',
            lambda n: f"REDACTED_SECRET_{n}")

    def _anonymize_secret_value(self, match: re.Match) -> str:
        prefix = match.group(1)  # e.g., 'password = "'
        value = match.group(2)   # the actual secret value
        # Skip if already redacted by a previous pattern
        if value.startswith('REDACTED_SECRET_'):
            return match.group(0)
        pseudo = self._get_or_create(value, 'secret',
            lambda n: f"REDACTED_SECRET_{n}")
        return f"{prefix}{pseudo}"

    def _anonymize_connection_string(self, match: re.Match) -> str:
        original = match.group(0)
        protocol = original.split('://')[0]
        return self._get_or_create(original, 'secret',
            lambda n: f"{protocol}://user:REDACTED_SECRET_{n}@redacted-host.example.com:5432/db")

    def _anonymize_bucket(self, match: re.Match) -> str:
        original = match.group(0)
        return self._get_or_create(original, 'bucket',
            lambda n: f"redacted-bucket-{n}")
