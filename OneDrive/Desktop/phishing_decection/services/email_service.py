"""Email phishing analysis service."""

from __future__ import annotations

import re
from typing import Any

from utils.validation import sanitize_text


class EmailAnalyzer:
    KEYWORDS = ["urgent", "verify", "password", "otp", "invoice", "payment", "suspended", "winner", "gift"]

    def analyze(self, content: str) -> dict[str, Any]:
        text = sanitize_text(content)
        urls = sorted(set(re.findall(r"https?://[^\s<>\"]+", text)))
        lower = text.lower()
        findings = []
        score = 0
        matched = [word for word in self.KEYWORDS if word in lower]
        if matched:
            score += min(35, len(matched) * 7)
            findings.append(f"Social engineering keywords detected: {', '.join(matched)}")
        if re.search(r"from:\s*.*@.*\n.*reply-to:\s*.*@", lower):
            score += 18
            findings.append("Different From and Reply-To headers may indicate sender spoofing")
        if urls:
            score += min(30, len(urls) * 10)
            findings.append(f"{len(urls)} embedded URL(s) found")
        if re.search(r"act now|within 24 hours|immediately", lower):
            score += 20
            findings.append("Urgency language detected")
        verdict = "phishing" if score >= 60 else "suspicious" if score >= 30 else "safe"
        return {
            "verdict": verdict,
            "risk_score": min(100, score),
            "embedded_urls": urls,
            "findings": findings or ["No obvious phishing language found"],
            "recommended_actions": ["Scan every embedded URL before clicking", "Verify sender through a trusted channel"],
        }
