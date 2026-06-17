"""
PhishGuard detection engine.

This module combines a transparent rule-based URL intelligence engine with a
Random Forest classifier and optional Google Safe Browsing verification.
"""

from __future__ import annotations

import ipaddress
import math
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

import joblib
import requests


@dataclass
class FeatureSet:
    url_length: int
    domain_length: int
    dot_count: int
    has_https: int
    special_char_count: int
    digit_count: int
    hyphen_count: int
    subdomain_count: int
    suspicious_keyword_count: int
    has_at_symbol: int
    is_ip_address: int
    is_shortener: int
    has_brand_spoof: int
    has_risky_tld: int
    entropy_scaled: int

    def as_model_row(self) -> List[int]:
        return [
            self.url_length,
            self.domain_length,
            self.dot_count,
            self.has_https,
            self.special_char_count,
            self.digit_count,
            self.hyphen_count,
            self.subdomain_count,
            self.suspicious_keyword_count,
            self.has_at_symbol,
            self.is_ip_address,
            self.is_shortener,
            self.has_brand_spoof,
            self.has_risky_tld,
            self.entropy_scaled,
        ]


class PhishingDetector:
    SUSPICIOUS_KEYWORDS = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "bank",
        "free",
        "reward",
        "gift",
        "claim",
        "payment",
        "invoice",
        "billing",
        "crypto",
        "wallet",
        "otp",
        "password",
        "confirm",
        "details",
    ]

    TRUSTED_BRANDS = [
        "google",
        "apple",
        "amazon",
        "paypal",
        "microsoft",
        "facebook",
        "netflix",
        "instagram",
        "whatsapp",
        "linkedin",
        "bankofamerica",
        "icici",
        "hdfc",
        "sbi",
    ]

    SHORTENERS = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "is.gd",
        "cutt.ly",
        "rebrand.ly",
        "shorturl.at",
        "short.link",
    ]

    RISKY_TLDS = {"xyz", "top", "click", "ru", "tk", "zip", "mov", "gq", "cf", "work", "quest"}
    COMMON_SECOND_LEVEL_TLDS = {"co", "com", "net", "org", "gov", "edu", "ac"}
    COUNTRY_TLDS = {
        "in": "India",
        "au": "Australia",
        "uk": "United Kingdom",
        "us": "United States",
        "ca": "Canada",
        "de": "Germany",
        "fr": "France",
        "jp": "Japan",
        "cn": "China",
        "br": "Brazil",
        "ru": "Russia",
        "tk": "Tokelau",
        "co": "Colombia",
        "za": "South Africa",
        "sg": "Singapore",
        "ae": "United Arab Emirates",
        "nz": "New Zealand",
        "it": "Italy",
        "es": "Spain",
        "nl": "Netherlands",
        "ch": "Switzerland",
        "se": "Sweden",
        "no": "Norway",
        "fi": "Finland",
        "ie": "Ireland",
        "mx": "Mexico",
    }
    GENERIC_TLDS = {"com", "org", "net", "info", "io", "ai", "edu", "gov", "mil"}

    LOCAL_BLACKLIST = {
        "secure-login-google.com",
        "paypal-security-update.com",
        "wallet-bonus-gift-claim.xyz",
    }

    def __init__(
        self,
        api_key: str | None = None,
        model_path: str | None = None,
        enable_redirects: bool = True,
        enable_ssl: bool = True,
    ):
        self.api_key = api_key
        self.enable_redirects = enable_redirects
        self.enable_ssl = enable_ssl
        self.safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        default_model = Path(__file__).resolve().parent / "models" / "model.pkl"
        self.model_path = Path(model_path) if model_path else default_model
        self.model = self._load_model()
        self._domain_cache: Dict[str, Dict[str, str]] = {}

    @property
    def model_loaded(self) -> bool:
        return self.model is not None

    def analyze(self, raw_url: str) -> Dict[str, Any]:
        """Analyze a URL and return a full threat intelligence payload."""
        normalized_url = self._normalize_url(raw_url)
        parsed = urlparse(normalized_url)
        domain = parsed.hostname.lower() if parsed.hostname else ""

        features = self._build_features(normalized_url, domain)
        analysis, rule_score = self._rule_score(normalized_url, parsed, domain, features)

        ml_probability = self._predict_ml_probability(features)
        ml_score = ml_probability * 100
        if self.model_loaded:
            analysis.append(f"ML phishing probability: {ml_score:.1f}%")
        else:
            analysis.append("ML model unavailable; rule engine fallback is active")

        safe_browsing_threats = self._check_safe_browsing(normalized_url)
        redirect_info = self._redirect_analysis(normalized_url)
        ssl_info = self._ssl_verification(parsed, domain)
        source_parts = ["Rule Engine"]
        if self.model_loaded:
            source_parts.append("Random Forest ML")
        if safe_browsing_threats:
            source_parts.append("Google Safe Browsing")
            for threat in safe_browsing_threats:
                analysis.append(f"Google Safe Browsing threat: {threat}")

        if domain in self.LOCAL_BLACKLIST:
            combined_blacklist_score = 94
            analysis.append("Domain matched the local phishing reputation list")
        else:
            combined_blacklist_score = 0

        if redirect_info["redirect_count"] > 2:
            analysis.append(f"Multiple redirects detected: {redirect_info['redirect_count']}")
        elif redirect_info["redirect_count"] > 0:
            analysis.append(f"Redirect detected to {redirect_info['final_url']}")

        if ssl_info["checked"] and not ssl_info["valid"]:
            analysis.append(f"SSL verification issue: {ssl_info['message']}")

        combined_score = max(rule_score, (rule_score * 0.68) + (ml_score * 0.32))
        if safe_browsing_threats:
            combined_score = max(combined_score, 92)
        if combined_blacklist_score:
            source_parts.append("Local Reputation")
            combined_score = max(combined_score, combined_blacklist_score)
        if redirect_info["redirect_count"] > 2:
            combined_score = max(combined_score, 55)
        if ssl_info["checked"] and not ssl_info["valid"]:
            combined_score = max(combined_score, 42)

        strong_brand_spoof = bool(features.has_brand_spoof and rule_score >= 45)
        if features.has_at_symbol or strong_brand_spoof:
            combined_score = max(combined_score, 65)

        risk_score = min(100, round(combined_score))
        verdict, risk_level, confidence = self._classify_url(normalized_url, risk_score)
        domain_info = self._domain_intelligence(domain)
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

        if not analysis:
            analysis.append("No suspicious indicators detected")

        return {
            "verdict": verdict,
            "confidence": confidence,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "domain": domain,
            "registrar": domain_info["registrar"],
            "country": domain_info["country"],
            "domain_age": domain_info["domain_age"],
            "timestamp": timestamp,
            "favicon": f"https://www.google.com/s2/favicons?domain={domain}&sz=64",
            "source": " + ".join(source_parts),
            "recommendation": self._recommendation(verdict),
            "recommended_actions": self._recommended_actions(verdict, features, safe_browsing_threats),
            "analysis": analysis,
            "redirect_analysis": redirect_info,
            "ssl_verification": ssl_info,
            "reputation": {
                "local_blacklist": domain in self.LOCAL_BLACKLIST,
                "google_safe_browsing": safe_browsing_threats,
            },
            "ml_probability": round(ml_score, 1),
            "ml_confidence": round(abs(ml_probability - 0.5) * 200, 1),
            "domain_info": domain_info,
            "features": {
                "url_length": features.url_length,
                "dots": features.dot_count,
                "hyphens": features.hyphen_count,
                "subdomains": features.subdomain_count,
                "keywords": features.suspicious_keyword_count,
                "special_characters": features.special_char_count,
                "digits": features.digit_count,
                "risky_tld": bool(features.has_risky_tld),
            },
        }

    def _load_model(self):
        """Load the trained Random Forest model if it is available."""
        if not self.model_path.exists():
            return None
        try:
            return joblib.load(self.model_path)
        except Exception:
            return None

    def _normalize_url(self, url: str) -> str:
        cleaned = url.strip()
        if not cleaned.startswith(("http://", "https://")):
            cleaned = "http://" + cleaned
        return cleaned

    def _build_features(self, url: str, domain: str) -> FeatureSet:
        lower_url = url.lower()
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        return FeatureSet(
            url_length=len(url),
            domain_length=len(domain),
            dot_count=url.count("."),
            has_https=1 if lower_url.startswith("https://") else 0,
            special_char_count=len(re.findall(r"[^a-zA-Z0-9]", url)),
            digit_count=len(re.findall(r"\d", url)),
            hyphen_count=domain.count("-"),
            subdomain_count=self._subdomain_count(domain),
            suspicious_keyword_count=sum(1 for word in self.SUSPICIOUS_KEYWORDS if word in lower_url),
            has_at_symbol=1 if "@" in url else 0,
            is_ip_address=1 if self._is_ip(domain) else 0,
            is_shortener=1 if any(domain == s or domain.endswith("." + s) for s in self.SHORTENERS) else 0,
            has_brand_spoof=1 if self._brand_spoofed(domain) else 0,
            has_risky_tld=1 if tld in self.RISKY_TLDS else 0,
            entropy_scaled=int(self._entropy(domain) * 100),
        )

    def _rule_score(self, url: str, parsed, domain: str, features: FeatureSet):
        """Convert observable URL indicators into an analyst-readable risk score."""
        score = 0.0
        analysis: List[str] = []
        lower_url = url.lower()
        is_local_ip = self._is_private_ip(domain)

        if not features.has_https:
            if is_local_ip:
                analysis.append("HTTP used on a private or local network target")
            else:
                score += 12
                analysis.append("HTTPS is not enabled")

        if features.url_length > 100:
            score += 12
            analysis.append("URL length is unusually high")
        elif features.url_length > 75:
            score += 6
            analysis.append("URL is longer than normal")

        if features.has_at_symbol:
            score += 50
            target = lower_url.split("@")[-1].split("/")[0]
            analysis.append("Dangerous @ symbol pattern detected")
            analysis.append(f"Browser target after @ symbol: {target}")

        if features.is_ip_address:
            if is_local_ip:
                analysis.append("Private or local IP address detected")
            else:
                score += 30
                analysis.append("IP address URL detected")

        if features.suspicious_keyword_count:
            score += min(34, features.suspicious_keyword_count * 7)
            found = [word for word in self.SUSPICIOUS_KEYWORDS if word in lower_url]
            analysis.append(f"Suspicious keyword: {', '.join(found[:8])}")

        if features.hyphen_count >= 3:
            score += 16
            analysis.append("Multiple hyphens detected")
        elif features.hyphen_count:
            score += 5
            analysis.append("Hyphen detected in domain")

        if features.subdomain_count > 3:
            score += 18
            analysis.append("Too many subdomains detected")
        elif features.subdomain_count > 2:
            score += 10
            analysis.append("Multiple subdomains detected")

        if features.has_brand_spoof:
            score += 52
            analysis.append("Brand spoofing detected")

        if features.is_shortener:
            score += 20
            analysis.append("URL shortener detected")

        if features.domain_length > 35:
            score += 14
            analysis.append("Very long domain detected")
        elif features.domain_length > 28:
            score += 7
            analysis.append("Long domain detected")

        if re.search(r"\.com\.(?![a-z]{2}$)[a-z]{2,}", domain):
            score += 30
            analysis.append("brand.com.fake-domain pattern detected")

        if re.search(r"\d", domain) and not is_local_ip:
            score += 8
            analysis.append("Numbers detected in domain")

        if features.has_risky_tld:
            score += 18
            analysis.append(f"Suspicious TLD detected: .{domain.rsplit('.', 1)[-1]}")

        if features.special_char_count > 25:
            score += 8
            analysis.append("High number of special characters detected")

        if parsed.port and parsed.port not in (80, 443):
            score += 10
            analysis.append(f"Non-standard port detected: {parsed.port}")

        return analysis, min(100.0, score)

    def _predict_ml_probability(self, features: FeatureSet) -> float:
        """Return the phishing probability from the model or a deterministic fallback."""
        if not self.model:
            rule_hint = (
                features.has_at_symbol * 0.35
                + features.has_brand_spoof * 0.3
                + features.has_risky_tld * 0.14
                + features.is_shortener * 0.12
                + min(features.suspicious_keyword_count / 8, 0.2)
                + min(features.entropy_scaled / 650, 0.15)
                + min(features.url_length / 500, 0.15)
            )
            return min(0.98, rule_hint)

        try:
            if hasattr(self.model, "predict_proba"):
                return float(self.model.predict_proba([features.as_model_row()])[0][1])
            return float(self.model.predict([features.as_model_row()])[0])
        except Exception:
            return 0.0

    def _check_safe_browsing(self, url: str) -> List[str]:
        if not self.api_key:
            return []

        payload = {
            "client": {"clientId": "phishguard", "clientVersion": "2.1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            response = requests.post(f"{self.safe_browsing_url}?key={self.api_key}", json=payload, timeout=8)
            response.raise_for_status()
            matches = response.json().get("matches", [])
            return sorted({match.get("threatType", "UNKNOWN_THREAT") for match in matches})
        except requests.RequestException:
            return []

    def _redirect_analysis(self, url: str) -> Dict[str, Any]:
        if not self.enable_redirects:
            return {"checked": False, "redirect_count": 0, "final_url": url, "chain": []}

        parsed = urlparse(url)
        host = parsed.hostname or ""
        if self._is_private_ip(host):
            return {
                "checked": False,
                "redirect_count": 0,
                "final_url": url,
                "chain": [],
                "message": "Redirect lookup skipped for private network target",
            }

        try:
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=2.5,
                headers={"User-Agent": "PhishGuard/3.0 URL safety scanner"},
                stream=True,
            )
            chain = [item.url for item in response.history] + [response.url]
            response.close()
            return {
                "checked": True,
                "redirect_count": max(0, len(chain) - 1),
                "final_url": chain[-1] if chain else url,
                "chain": chain[:8],
            }
        except requests.RequestException:
            return {
                "checked": True,
                "redirect_count": 0,
                "final_url": url,
                "chain": [],
                "message": "Redirect lookup unavailable",
            }

    def _ssl_verification(self, parsed, domain: str) -> Dict[str, Any]:
        if not self.enable_ssl or parsed.scheme != "https" or not domain or self._is_ip(domain):
            return {"checked": False, "valid": False, "message": "SSL verification not applicable"}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=2.5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    certificate = secure_sock.getpeercert()
            not_after = certificate.get("notAfter")
            return {
                "checked": True,
                "valid": True,
                "issuer": self._certificate_name(certificate.get("issuer", [])),
                "expires_at": not_after or "Not available",
                "message": "Valid HTTPS certificate",
            }
        except (OSError, ssl.SSLError, ValueError) as exc:
            return {"checked": True, "valid": False, "message": str(exc)[:160]}

    def _brand_spoofed(self, domain: str) -> bool:
        """Detect fake brand usage while allowing legitimate domains and subdomains."""
        if not domain:
            return False

        registered = self._registered_domain(domain)
        registered_brand = registered.split(".")[0]
        for brand in self.TRUSTED_BRANDS:
            if brand not in domain:
                continue
            if registered_brand == brand:
                return False
            suspicious_patterns = [
                rf"{re.escape(brand)}[-.]?(login|secure|verify|account|payment|wallet)",
                rf"(login|secure|verify|account|payment|wallet)[-.]?{re.escape(brand)}",
                rf"{re.escape(brand)}\.com\.",
            ]
            if any(re.search(pattern, domain) for pattern in suspicious_patterns):
                return True
            return True
        return False

    def _registered_domain(self, domain: str) -> str:
        labels = domain.split(".")
        if len(labels) <= 2:
            return domain
        if labels[-2] in self.COMMON_SECOND_LEVEL_TLDS and len(labels[-1]) == 2:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    def _subdomain_count(self, domain: str) -> int:
        if not domain or self._is_ip(domain):
            return 0
        registered = self._registered_domain(domain)
        if domain == registered:
            return 0
        return max(0, len(domain.removesuffix("." + registered).split(".")))

    def _is_ip(self, domain: str) -> bool:
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False

    def _is_private_ip(self, domain: str) -> bool:
        try:
            return ipaddress.ip_address(domain).is_private
        except ValueError:
            return False

    def _classify_url(self, url: str, risk_score: int):
        """Apply the final rounded-threshold verdict and confidence rules."""
        if "@" in url or risk_score >= 60:
            return "phishing", "HIGH", min(98, risk_score + 30)
        if risk_score >= 30:
            return "suspicious", "MEDIUM", 60 + int(risk_score / 2)
        return "safe", "LOW", max(100 - risk_score, 70)

    def _confidence(self, risk_score: float, ml_probability: float, safe_browsing_hit: bool) -> int:
        if safe_browsing_hit:
            return 98
        distance = abs(risk_score - 50) / 50
        model_weight = abs(ml_probability - 0.5) * 30
        return int(max(72, min(98, 72 + (distance * 22) + model_weight)))

    def _recommendation(self, verdict: str) -> str:
        if verdict == "phishing":
            return "Do not open this URL or enter credentials. Block and report it."
        if verdict == "suspicious":
            return "Verify the domain, certificate, and sender before continuing."
        return "No major threat indicators found. Continue with normal caution."

    def _recommended_actions(self, verdict: str, features: FeatureSet, threats: List[str]) -> List[str]:
        if verdict == "phishing":
            actions = [
                "Do not enter credentials, OTPs, payment details, or wallet keys.",
                "Block the URL at gateway, browser, DNS, or MDM policy level.",
                "Report the URL to the security team or abuse desk.",
            ]
            if threats:
                actions.append("Escalate immediately because an external blacklist confirmed the threat.")
            return actions

        if verdict == "suspicious":
            actions = [
                "Manually verify the registered domain and sender identity.",
                "Open only in an isolated browser or sandbox if business review is required.",
            ]
            if features.has_brand_spoof:
                actions.append("Contact the impersonated brand through an official channel.")
            return actions

        return [
            "Proceed only if the source of the URL is trusted.",
            "Avoid entering sensitive data unless the page content also looks legitimate.",
        ]

    def _entropy(self, value: str) -> float:
        if not value:
            return 0.0
        probabilities = [value.count(char) / len(value) for char in set(value)]
        return -sum(probability * math.log2(probability) for probability in probabilities)

    def _domain_intelligence(self, domain: str) -> Dict[str, str]:
        if self._is_ip(domain):
            return {
                "registrar": "IP address target",
                "country": "Private network" if self._is_private_ip(domain) else "Not available",
                "domain_age": "Not applicable",
            }

        registered_domain = self._registered_domain(domain)
        if registered_domain in self._domain_cache:
            return self._domain_cache[registered_domain]

        fallback = {
            "registrar": "Not available from registry",
            "country": self._country_from_tld(registered_domain),
            "domain_age": "Not available from registry",
        }

        try:
            response = requests.get(f"https://rdap.org/domain/{registered_domain}", timeout=2.5)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException:
            self._domain_cache[registered_domain] = fallback
            return fallback

        result = {
            "registrar": self._extract_registrar(data) or fallback["registrar"],
            "country": self._extract_country(data) or self._country_from_tld(registered_domain),
            "domain_age": self._extract_domain_age(data) or fallback["domain_age"],
        }
        self._domain_cache[registered_domain] = result
        return result

    def _extract_registrar(self, rdap_data: Dict[str, Any]) -> str | None:
        for entity in rdap_data.get("entities", []):
            if "registrar" not in entity.get("roles", []):
                continue
            name = self._vcard_value(entity, "fn") or entity.get("handle")
            if name:
                return name
        return None

    def _country_from_tld(self, domain: str) -> str:
        tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
        if tld in self.COUNTRY_TLDS:
            return self.COUNTRY_TLDS[tld]
        if tld in self.GENERIC_TLDS:
            return f"Generic global domain (.{tld})"
        return "Not available"

    def _extract_country(self, rdap_data: Dict[str, Any]) -> str | None:
        for entity in rdap_data.get("entities", []):
            country = self._vcard_value(entity, "adr", country_only=True)
            if country:
                return country
        return None

    def _extract_domain_age(self, rdap_data: Dict[str, Any]) -> str | None:
        created_at = None
        for event in rdap_data.get("events", []):
            if event.get("eventAction") in {"registration", "created"}:
                created_at = event.get("eventDate")
                break
        if not created_at:
            return None

        try:
            created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except ValueError:
            return None

        now = datetime.now(timezone.utc)
        months = max(0, (now.year - created.year) * 12 + now.month - created.month)
        years, remaining_months = divmod(months, 12)
        if years and remaining_months:
            return f"{years} years {remaining_months} months"
        if years:
            return f"{years} years"
        return f"{remaining_months} months"

    def _vcard_value(self, entity: Dict[str, Any], key: str, country_only: bool = False) -> str | None:
        vcard = entity.get("vcardArray", [])
        if len(vcard) < 2:
            return None
        for item in vcard[1]:
            if not item or item[0] != key:
                continue
            value = item[3]
            if country_only and key == "adr" and isinstance(value, list) and value:
                country = value[-1]
                return country if isinstance(country, str) and country.strip() else None
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _certificate_name(self, parts: list) -> str:
        names = []
        for section in parts:
            for key, value in section:
                if key in {"organizationName", "commonName"} and value:
                    names.append(value)
        return ", ".join(names[:2]) or "Not available"
