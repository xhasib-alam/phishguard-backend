"""URL scan orchestration and persistence."""

from __future__ import annotations

from typing import Any

from database import get_db, json_dumps, json_loads, now_iso, transaction
from detector import PhishingDetector


class ScanService:
    def __init__(self, detector: PhishingDetector):
        self.detector = detector

    def scan_url(self, url: str, user_id: int | None = None, persist: bool = True) -> dict[str, Any]:
        result = self.detector.analyze(url)
        if persist:
            result["scan_id"] = self.save_scan(url, result, user_id)
        return result

    def save_scan(self, url: str, result: dict[str, Any], user_id: int | None = None) -> int:
        with transaction() as db:
            cursor = db.execute(
                """
                INSERT INTO scans (user_id, url, domain, verdict, risk_score, confidence, source, result_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    url,
                    result.get("domain"),
                    result.get("verdict"),
                    int(result.get("risk_score", 0)),
                    int(result.get("confidence", 0)),
                    result.get("source"),
                    json_dumps(result),
                    now_iso(),
                ),
            )
            db.execute(
                "INSERT INTO audit_logs (user_id, action, metadata_json, created_at) VALUES (?, ?, ?, ?)",
                (user_id, "scan.created", json_dumps({"url": url, "verdict": result.get("verdict")}), now_iso()),
            )
            return int(cursor.lastrowid)

    def history(self, user_id: int | None = None, query: str = "", verdict: str = "", limit: int = 50) -> list[dict]:
        sql = "SELECT * FROM scans WHERE 1=1"
        params: list[Any] = []
        if user_id:
            sql += " AND user_id = ?"
            params.append(user_id)
        if query:
            sql += " AND (url LIKE ? OR domain LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%"])
        if verdict:
            sql += " AND verdict = ?"
            params.append(verdict)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = get_db().execute(sql, params).fetchall()
        return [self._history_row(row) for row in rows]

    def analytics(self, user_id: int | None = None) -> dict[str, Any]:
        where = "WHERE user_id = ?" if user_id else ""
        params = (user_id,) if user_id else ()
        rows = get_db().execute(
            f"SELECT verdict, COUNT(*) AS total FROM scans {where} GROUP BY verdict",
            params,
        ).fetchall()
        counts = {row["verdict"]: row["total"] for row in rows}
        total = sum(counts.values())
        recent = self.history(user_id=user_id, limit=8)
        brands = self._targeted_brands(user_id)
        return {
            "total_scans": total,
            "safe": counts.get("safe", 0),
            "suspicious": counts.get("suspicious", 0),
            "phishing": counts.get("phishing", 0),
            "recent_threats": [item for item in recent if item["verdict"] != "safe"][:5],
            "most_targeted_brands": brands,
            "threat_trends": counts,
        }

    def _targeted_brands(self, user_id: int | None) -> list[dict[str, Any]]:
        where = "WHERE user_id = ?" if user_id else ""
        params = (user_id,) if user_id else ()
        rows = get_db().execute(f"SELECT result_json FROM scans {where} ORDER BY id DESC LIMIT 200", params).fetchall()
        counts: dict[str, int] = {}
        for row in rows:
            result = json_loads(row["result_json"])
            text = " ".join(result.get("analysis", [])).lower()
            for brand in self.detector.TRUSTED_BRANDS:
                if brand in result.get("domain", "").lower() or brand in text:
                    counts[brand] = counts.get(brand, 0) + 1
        return [{"brand": brand, "count": count} for brand, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:8]]

    def _history_row(self, row) -> dict:
        return {
            "id": row["id"],
            "url": row["url"],
            "domain": row["domain"],
            "verdict": row["verdict"],
            "risk_score": row["risk_score"],
            "confidence": row["confidence"],
            "source": row["source"],
            "created_at": row["created_at"],
            "result": json_loads(row["result_json"]),
        }
