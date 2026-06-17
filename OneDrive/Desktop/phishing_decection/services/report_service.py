"""Report creation and PDF generation."""

from __future__ import annotations

import re
from typing import Any

from database import json_dumps, now_iso, transaction
from database import get_db, json_loads


class ReportService:
    def create_report(self, result: dict[str, Any], user_id: int | None = None) -> dict[str, Any]:
        report = {
            "title": "PhishGuard URL Threat Report",
            "summary": f"{result.get('domain')} classified as {str(result.get('verdict')).upper()} with risk score {result.get('risk_score')}/100.",
            "result": result,
            "recommended_actions": result.get("recommended_actions", []),
            "created_at": now_iso(),
        }
        with transaction() as db:
            cursor = db.execute(
                "INSERT INTO reports (scan_id, user_id, title, report_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (result.get("scan_id"), user_id, report["title"], json_dumps(report), report["created_at"]),
            )
            report["id"] = cursor.lastrowid
        return report

    def get_report(self, report_id: int, user_id: int | None = None) -> dict[str, Any] | None:
        sql = "SELECT * FROM reports WHERE id = ?"
        params: list[Any] = [report_id]
        if user_id:
            sql += " AND user_id = ?"
            params.append(user_id)
        row = get_db().execute(sql, params).fetchone()
        if not row:
            return None
        report = json_loads(row["report_json"])
        report["id"] = row["id"]
        report["created_at"] = row["created_at"]
        return report

    def pdf(self, report: dict[str, Any]) -> bytes:
        result = report["result"]
        lines = [
            report["title"],
            report["summary"],
            "",
            f"URL: {result.get('url', '-')}",
            f"Domain: {result.get('domain', '-')}",
            f"Verdict: {str(result.get('verdict', '-')).upper()}",
            f"Confidence: {result.get('confidence', 0)}%",
            f"Risk Score: {result.get('risk_score', 0)}/100",
            f"Risk Level: {result.get('risk_level', '-')}",
            f"Detection Source: {result.get('source', '-')}",
            f"Timestamp: {result.get('timestamp', '-')}",
            "",
            "Findings:",
        ]
        lines.extend(f"- {item}" for item in result.get("analysis", []))
        lines.extend(["", "Recommendations:"])
        lines.extend(f"- {item}" for item in result.get("recommended_actions", []))
        return simple_pdf(lines)


def simple_pdf(lines: list[str]) -> bytes:
    wrapped = []
    for line in lines:
        if not line:
            wrapped.append("")
            continue
        while len(line) > 92:
            wrapped.append(line[:92])
            line = line[92:]
        wrapped.append(line)

    content_lines = ["BT", "/F1 10 Tf", "50 790 Td", "14 TL"]
    for index, line in enumerate(wrapped[:52]):
        if index:
            content_lines.append("T*")
        content_lines.append(f"({escape_pdf(line)}) Tj")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", errors="replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode())
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")
    xref_at = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode())
    pdf.extend(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF".encode())
    return bytes(pdf)


def escape_pdf(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def safe_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9.-]+", "-", value).strip("-") or "report"
