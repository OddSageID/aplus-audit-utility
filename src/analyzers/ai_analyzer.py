from typing import Dict, Any, List, Optional
import json
import asyncio
import logging
from anthropic import Anthropic
from openai import OpenAI
from pydantic import ValidationError

from ..core.rate_limiter import RateLimiter, RateLimitedAPIClient, RateLimitConfig
from ..core.validation import validate_ai_response, AIAnalysisResponseSchema


class AIAnalyzer:
    """
    AI-powered analysis using Claude or GPT.
    Includes rate limiting, circuit breaker, and response validation.
    """
    
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
            request_timeout_seconds=30
        )
        self.rate_limiter = RateLimiter(rate_limit_config)
        
        # Initialize API client
        if config.provider == "anthropic":
            base_client = Anthropic(api_key=config.api_key)
        elif config.provider == "openai":
            base_client = OpenAI(api_key=config.api_key)
        else:
            base_client = None
        
        self.client = RateLimitedAPIClient(base_client, self.rate_limiter) if base_client else None
        
        # Metrics tracking
        self.total_api_calls = 0
        self.total_api_errors = 0
        self.total_latency_ms = 0.0
    
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
            start_time = asyncio.get_event_loop().time()
            
            if self.config.provider == "anthropic":
                response = await self.client.create_message(
                    model=self.config.model,
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    messages=[{"role": "user", "content": prompt}]
                )
                content = response.content[0].text
            else:
                response = await self.client.create_completion(
                    model=self.config.model,
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    messages=[{"role": "user", "content": prompt}]
                )
                content = response.choices[0].message.content
            
            # Track metrics
            self.total_api_calls += 1
            latency = (asyncio.get_event_loop().time() - start_time) * 1000
            self.total_latency_ms += latency
            
            # Parse and validate response
            try:
                response_data = json.loads(content)
                validated = validate_ai_response(response_data)
                return validated.dict()
            except (json.JSONDecodeError, ValidationError) as e:
                self.logger.error(f"Invalid AI response: {e}")
                self.total_api_errors += 1
                return self._fallback_analysis(findings)
                
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
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
                    messages=[{"role": "user", "content": prompt}]
                )
                script = response.content[0].text.strip()
            else:
                response = await self.client.create_completion(
                    model=self.config.model,
                    max_tokens=2048,
                    temperature=0.1,
                    messages=[{"role": "user", "content": prompt}]
                )
                script = response.choices[0].message.content.strip()
            
            # Remove markdown code blocks if present
            script = script.replace('```bash', '').replace('```powershell', '').replace('```', '').strip()
            
            self.total_api_calls += 1
            return script
            
        except Exception as e:
            self.logger.error(f"Remediation script generation failed: {e}")
            self.total_api_errors += 1
            return self._fallback_remediation_script(finding, platform)
    
    def _build_analysis_prompt(self, audit_data: Dict, findings: List[Dict]) -> str:
        """Build prompt for AI analysis"""
        findings_text = "\n".join([
            f"- [{f['severity']}] {f['check_id']}: {f['description']}"
            for f in findings[:50]  # Limit to prevent token overflow
        ])
        
        return f"""Analyze this system security audit and provide a JSON response with the following structure:
{{
    "risk_score": <integer 0-100>,
    "executive_summary": "<concise 2-3 sentence summary>",
    "critical_issues": ["<critical issue 1>", "<critical issue 2>"],
    "recommendations": ["<actionable recommendation 1>", "<actionable recommendation 2>"]
}}

System Information:
- Platform: {audit_data.get('platform', 'Unknown')}
- Hostname: {audit_data.get('hostname', 'Unknown')}

Findings ({len(findings)} total):
{findings_text}

Provide ONLY the JSON response, no additional text."""
    
    def _fallback_analysis(self, findings: List[Dict]) -> Dict[str, Any]:
        """Fallback analysis when AI is unavailable"""
        severity_weights = {'CRITICAL': 25, 'HIGH': 15, 'MEDIUM': 8, 'LOW': 3, 'INFO': 1}
        risk_score = min(100, sum(severity_weights.get(f['severity'], 0) for f in findings))
        
        critical_issues = [
            f"{f['check_id']}: {f['description']}"
            for f in findings if f['severity'] == 'CRITICAL'
        ][:10]  # Limit to 10
        
        return {
            'risk_score': risk_score,
            'executive_summary': f"Audit identified {len(findings)} findings requiring attention. "
                               f"{len(critical_issues)} critical issues detected.",
            'critical_issues': critical_issues,
            'recommendations': [
                "Review and address critical findings immediately",
                "Apply security patches and updates",
                "Implement recommended security controls",
                "Schedule regular security audits"
            ]
        }
    
    def _fallback_remediation_script(self, finding: Dict, platform: str) -> str:
        """Fallback remediation script template"""
        if platform == "Windows":
            ext = "ps1"
            shebang = "# PowerShell Remediation Script"
        else:
            ext = "sh"
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
            self.total_latency_ms / self.total_api_calls
            if self.total_api_calls > 0 else 0
        )
        
        return {
            'total_api_calls': self.total_api_calls,
            'total_api_errors': self.total_api_errors,
            'avg_latency_ms': round(avg_latency, 2),
            'error_rate': (
                self.total_api_errors / self.total_api_calls
                if self.total_api_calls > 0 else 0
            ),
            'rate_limiter_stats': self.rate_limiter.get_stats() if self.rate_limiter else {}
        }
