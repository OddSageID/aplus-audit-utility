from typing import Dict, Any, List
import logging
import asyncio
import json
import time
import os

from pydantic import ValidationError

from ..core.rate_limiter import RateLimiter, RateLimitedAPIClient, RateLimitConfig
from ..core.validation import validate_ai_response


class AIAnalyzer:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Initialize rate limiter
        rate_limit_config = RateLimitConfig(
            max_requests_per_minute=config.max_requests_per_minute,
            max_requests_per_hour=config.max_requests_per_hour,
            max_concurrent_requests=config.max_concurrent_requests,
            failure_threshold=5,
            success_threshold=2,
            timeout_seconds=60,
            request_timeout_seconds=30,
        )
        self.rate_limiter = RateLimiter(rate_limit_config)

        # Initialize API client (SAFE: no key => no client => fallback)
        api_key = getattr(config, "api_key", None)
        provider = getattr(config, "provider", None)

        base_client = None
        testing_env = os.getenv("PYTEST_CURRENT_TEST") is not None
        if api_key and provider == "anthropic":
            from anthropic import Anthropic  # pylint: disable=import-outside-toplevel

            base_client = Anthropic(api_key=api_key)
        elif api_key and provider == "openai":
            from openai import OpenAI  # pylint: disable=import-outside-toplevel

            base_client = OpenAI(api_key=api_key)
        else:
            # No key, unsupported provider, or running under tests: disable AI
            self.logger.info(
                "AI analysis disabled (missing API key, unsupported provider, or test environment)"
            )

        if testing_env and base_client is not None:
            if not getattr(base_client, "__module__", "").startswith("unittest.mock"):
                # Avoid real network in tests unless a mock client was injected
                base_client = None

        self.client = RateLimitedAPIClient(base_client, self.rate_limiter) if base_client else None

        # Metrics tracking
        self.total_api_calls = 0
        self.total_api_errors = 0
        self.total_latency_ms = 0.0

    def _normalize_audit_results(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize audit results from multiple schema versions.

        Supports:
        - New orchestrator output: top-level platform/hostname + collector_results
        - Legacy output: metadata.platform / metadata.hostname + collectors
        """
        # Prefer already aggregated findings when present
        all_findings = audit_results.get("all_findings", [])
        if not all_findings:
            collectors = (
                audit_results.get("collector_results") or audit_results.get("collectors") or {}
            )
            for collector in collectors.values():
                if isinstance(collector, dict):
                    all_findings.extend(collector.get("findings", []))

        metadata = audit_results.get("metadata", {}) or {}
        platform_val = audit_results.get("platform") or metadata.get("platform")
        hostname_val = audit_results.get("hostname") or metadata.get("hostname")

        return {
            "findings": all_findings,
            "audit_data": {
                "platform": platform_val,
                "hostname": hostname_val,
            },
        }

    def analyze(self, audit_results: Dict) -> Dict[str, Any]:
        """
        Backwards-compatible synchronous entry point expected by tests.
        Aggregates findings from collectors and runs async analysis.
        """
        normalized = self._normalize_audit_results(audit_results)
        return self._run_sync(
            self.analyze_findings(
                audit_data=normalized["audit_data"], findings=normalized["findings"]
            )
        )

    @staticmethod
    def _run_sync(coro):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            new_loop = asyncio.new_event_loop()
            try:
                return new_loop.run_until_complete(coro)
            finally:
                new_loop.close()
        return asyncio.run(coro)

    async def analyze_findings(self, audit_data: Dict, findings: List[Dict]) -> Dict[str, Any]:
        """
        Analyze findings and generate risk assessment with validation.

        Args:
            audit_data: Complete audit data
            findings: List of findings to analyze

        Returns:
            Validated analysis results
        """
        if not self.client:
            self.logger.info("AI analysis disabled, using fallback")
            return self._fallback_analysis(findings)

        prompt = self._build_analysis_prompt(audit_data, findings)

        try:
            start_time = time.perf_counter()

            if self.config.provider == "anthropic":
                response = await self.client.create_message(
                    model=self.config.model,
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    messages=[{"role": "user", "content": prompt}],
                )
                content = response.content[0].text
            else:
                response = await self.client.create_completion(
                    model=self.config.model,
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    messages=[{"role": "user", "content": prompt}],
                )
                content = response.choices[0].message.content

            # Track metrics
            self.total_api_calls += 1
            latency = (time.perf_counter() - start_time) * 1000
            self.total_latency_ms += latency

            # Parse and validate response
            try:
                response_data = json.loads(content)
                validated = validate_ai_response(response_data)
                return validated.dict()
            except (json.JSONDecodeError, ValidationError) as e:
                self.logger.error("Invalid AI response: %s", e)
                self.total_api_errors += 1
                return self._fallback_analysis(findings)

        except Exception as e:  # pylint: disable=broad-exception-caught
            self.logger.error("AI analysis failed: %s", e)
            self.total_api_errors += 1
            return self._fallback_analysis(findings)

    async def generate_remediation_script(self, finding: Dict, platform: str) -> str:
        """
        Generate remediation script for a finding.

        Args:
            finding: Finding dictionary
            platform: Target platform (Windows/Linux/Darwin)

        Returns:
            Remediation script content
        """
        if not self.client:
            return self._fallback_remediation_script(finding, platform)

        prompt = f"""Generate a safe remediation script for:
Platform: {platform}
Issue: {finding['description']}
Current State: {finding['current_value']}
Expected State: {finding['expected_value']}

Requirements:
1. Include error handling
2. Add rollback capability if possible
3. Include comments explaining each step
4. Ensure idempotent operation
5. Output ONLY the script code, no markdown formatting

Script:"""

        try:
            if self.config.provider == "anthropic":
                response = await self.client.create_message(
                    model=self.config.model,
                    max_tokens=2048,
                    temperature=0.1,
                    messages=[{"role": "user", "content": prompt}],
                )
                script = response.content[0].text.strip()
            else:
                response = await self.client.create_completion(
                    model=self.config.model,
                    max_tokens=2048,
                    temperature=0.1,
                    messages=[{"role": "user", "content": prompt}],
                )
                script = response.choices[0].message.content.strip()

            # Remove markdown code blocks if present
            script = (
                script.replace("```bash", "")
                .replace("```powershell", "")
                .replace("```", "")
                .strip()
            )

            self.total_api_calls += 1
            return script

        except Exception as e:  # pylint: disable=broad-exception-caught
            self.logger.error("Remediation script generation failed: %s", e)
            self.total_api_errors += 1
            return self._fallback_remediation_script(finding, platform)

    def _build_analysis_prompt(self, audit_data: Dict, findings: List[Dict]) -> str:
        """Build prompt for AI analysis"""
        findings_text = "\n".join(
            [
                f"- [{f['severity']}] {f['check_id']}: {f['description']}"
                for f in findings[:50]  # Limit to prevent token overflow
            ]
        )

        return (
            "Analyze this system security audit and provide a JSON response with the following "
            "structure:\n"
            "{\n"
            '    "risk_score": <integer 0-100>,\n'
            '    "executive_summary": "<concise 2-3 sentence summary>",\n'
            '    "critical_issues": ["<critical issue 1>", "<critical issue 2>"],\n'
            '    "recommendations": ["<actionable recommendation 1>", "<actionable recommendation 2>"]\n'
            "}\n\n"
            "System Information:\n"
            f"- Platform: {audit_data.get('platform', 'Unknown')}\n"
            f"- Hostname: {audit_data.get('hostname', 'Unknown')}\n\n"
            f"Findings ({len(findings)} total):\n"
            f"{findings_text}\n\n"
            "Provide ONLY the JSON response, no additional text."
        )

    def _fallback_analysis(self, findings: List[Dict]) -> Dict[str, Any]:
        """Fallback analysis when AI is unavailable"""
        severity_weights = {
            "CRITICAL": 50,
            "HIGH": 25,
            "MEDIUM": 10,
            "LOW": 5,
            "INFO": 1,
        }
        risk_score = min(100, sum(severity_weights.get(f["severity"], 0) for f in findings))

        critical_issues = [
            f"{f['check_id']}: {f['description']}"
            for f in findings
            if f["severity"] in ("CRITICAL", "HIGH")
        ][
            :10
        ]  # Limit to 10

        return {
            "risk_score": risk_score,
            "executive_summary": f"Audit identified {len(findings)} findings requiring attention. "
            f"{len(critical_issues)} critical issues detected.",
            "critical_issues": critical_issues,
            "recommendations": [
                "Review and address critical findings immediately",
                "Apply security patches and updates",
                "Implement recommended security controls",
                "Schedule regular security audits",
            ],
        }

    def _fallback_remediation_script(self, finding: Dict, platform: str) -> str:
        """Fallback remediation script template"""
        if platform == "Windows":
            shebang = "# PowerShell Remediation Script"
        else:
            shebang = "#!/bin/bash"

        return f"""{shebang}
# Remediation for: {finding['check_id']}
# Issue: {finding['description']}
#
# Current State: {finding['current_value']}
# Expected State: {finding['expected_value']}
#
# MANUAL REMEDIATION REQUIRED
# This is a template script. Please review and customize before execution.
#
# Remediation hint: {finding.get('remediation_hint', 'No hint available')}

echo "WARNING: This script requires manual customization"
echo "Issue: {finding['description']}"
echo "Please refer to system documentation for proper remediation steps"
"""

    def get_metrics(self) -> Dict[str, Any]:
        """Get AI analyzer metrics"""
        avg_latency = (
            self.total_latency_ms / self.total_api_calls if self.total_api_calls > 0 else 0
        )

        return {
            "total_api_calls": self.total_api_calls,
            "total_api_errors": self.total_api_errors,
            "avg_latency_ms": round(avg_latency, 2),
            "error_rate": (
                self.total_api_errors / self.total_api_calls if self.total_api_calls > 0 else 0
            ),
            "rate_limiter_stats": (self.rate_limiter.get_stats() if self.rate_limiter else {}),
        }
