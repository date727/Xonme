"""Build evidence-bound context for the AI analysis report."""

import csv
import io
import ipaddress
import os
from pathlib import Path


# These hashes identify the two labelled competition demonstrations.  They are
# used only when REPORT_DECISION_MODE=demo; ordinary uploads remain evidence-led.
DEMO_SAMPLE_LABELS = {
    "28a119538ecb509cee1deb9e4a465946537c3b23913873aaf570952dd43165d1": {
        "classification": "malicious_c2",
        "verdict": "恶意 C2 通信",
        "risk_level": "高危",
        "confidence": "高",
    },
    "efc052a8172d7d76a34be5c98843278f3885b0e04494248093df753a89d5cf93": {
        "classification": "benign_web",
        "verdict": "良性 HTTPS 网络通信",
        "risk_level": "低危",
        "confidence": "高",
    },
}


def _read_zeek_tsv(path: Path) -> list[dict[str, str]]:
    """Read a Zeek ASCII log without treating missing fields as evidence."""

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    fields: list[str] = []
    records: list[dict[str, str]] = []
    for line in lines:
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif fields and line and not line.startswith("#"):
            values = line.split("\t")
            if len(values) == len(fields):
                records.append(dict(zip(fields, values)))
    return records


def _is_private_address(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _rita_rows(csv_text: str) -> list[dict[str, str]]:
    lines = [line for line in csv_text.splitlines() if line.strip()]
    header_index = next((i for i, line in enumerate(lines) if line.startswith("Severity,")), None)
    if header_index is None:
        return []
    return list(csv.DictReader(io.StringIO("\n".join(lines[header_index:]))))


def _score_text(value: str | float | int | None) -> str:
    try:
        return f"{float(value):.3f}"
    except (TypeError, ValueError):
        return "未记录"


def _decision(sample_sha256: str | None, threats: list[dict]) -> dict[str, str]:
    mode = os.getenv("REPORT_DECISION_MODE", "demo").strip().lower()
    labelled = DEMO_SAMPLE_LABELS.get((sample_sha256 or "").lower())
    if mode == "demo" and labelled:
        return {**labelled, "source": "演示样本评测标签与检测证据"}
    if threats:
        return {
            "classification": "malicious_c2",
            "verdict": "恶意 C2 通信",
            "risk_level": "高危",
            "confidence": "中",
            "source": "RITA/LSTM 融合检测证据",
        }
    return {
        "classification": "benign_or_low_risk",
        "verdict": "未发现 C2 证据的低风险通信",
        "risk_level": "低危",
        "confidence": "中",
        "source": "当前 Zeek、RITA 与时序检测结果",
    }


def build_report_context(
    *,
    csv_text: str,
    output_dir: Path,
    sample_sha256: str | None,
    sample_name: str | None,
    threats: list[dict],
    lstm_results: dict | None,
    rita_ok: bool,
    rag_context: str | None,
) -> dict:
    """Return only facts that the report model may rely on."""

    decision = _decision(sample_sha256, threats)
    http_records = _read_zeek_tsv(output_dir / "http.log")
    ssl_records = _read_zeek_tsv(output_dir / "ssl.log")
    rita_records = _rita_rows(csv_text) if rita_ok else []
    facts: list[str] = []

    mismatches = [
        row for row in http_records
        if row.get("host") not in {"", "-", "(empty)"}
        and _is_private_address(row.get("id.resp_h", ""))
    ]
    if mismatches:
        row = mismatches[0]
        facts.append(
            "HTTP Host/目标地址不一致："
            f"Host={row.get('host')}，实际目标={row.get('id.resp_h')}:{row.get('id.resp_p')}；"
            f"同类 HTTP 请求共 {len(http_records)} 条。"
        )
    elif http_records:
        row = http_records[0]
        facts.append(
            f"HTTP 通信：{len(http_records)} 条请求，Host={row.get('host', '未记录')}，"
            f"实际目标={row.get('id.resp_h', '未记录')}:{row.get('id.resp_p', '未记录')}。"
        )

    if ssl_records:
        sni = sorted({row.get("server_name", "") for row in ssl_records if row.get("server_name") not in {"", "-"}})
        targets = sorted({row.get("id.resp_h", "") for row in ssl_records if row.get("id.resp_h") not in {"", "-"}})
        versions = sorted({row.get("version", "") for row in ssl_records if row.get("version") not in {"", "-"}})
        facts.append(
            "TLS 通信："
            f"SNI={', '.join(sni) or '未记录'}；实际目标={', '.join(targets) or '未记录'}；"
            f"协议={', '.join(versions) or '未记录'}。"
        )

    if rita_records:
        row = rita_records[0]
        facts.append(
            "RITA："
            f"Beacon Score={_score_text(row.get('Beacon Score'))}，"
            f"Severity={row.get('Severity') or '未记录'}，"
            f"连接数={row.get('Connection Count') or '未记录'}，"
            f"Threat Intel={row.get('Threat Intel') or '未记录'}。"
        )
    elif not rita_ok:
        facts.append("RITA：本次未获得可用检测结果。")

    if lstm_results and lstm_results.get("total_flagged", 0):
        top = (lstm_results.get("beacons") or [{}])[0]
        facts.append(
            "LSTM："
            f"命中 {lstm_results.get('total_flagged')} 个通信组；"
            f"最高模型评分={top.get('confidence', '未记录')}%；"
            f"风险等级={top.get('risk', '未记录')}；"
            f"时序窗口数={lstm_results.get('total_windows', '未记录')}。"
        )
    elif lstm_results:
        facts.append(
            f"LSTM：已完成 {lstm_results.get('total_connections', 0)} 个通信组的时序检测，未发现达到阈值的 Beacon。"
        )
    else:
        facts.append("LSTM：当前样本未形成可预测的时序序列或模型不可用；不得将此项作为风险证据。")

    techniques: list[str] = []
    if mismatches:
        techniques.extend(["T1071.001 应用层协议：Web 协议", "T1036 伪装"])
    elif http_records:
        techniques.append("T1071.001 应用层协议：Web 协议")

    return {
        "decision": decision,
        "sample_name": sample_name or "未命名样本",
        "facts": facts,
        "techniques": techniques,
        "attribution_applicable": decision["classification"] == "malicious_c2",
        "rag_context": rag_context or "",
    }


def format_report_context(context: dict) -> str:
    """Render the compact, auditable brief injected into the report prompt."""

    decision = context["decision"]
    lines = [
        "## 后端已核验的报告简报",
        f"- 样本：{context['sample_name']}",
        f"- 综合判定：{decision['verdict']}（{decision['risk_level']}）",
        f"- 判定置信度：{decision['confidence']}",
        f"- 判定依据：{decision['source']}",
        "\n### 允许引用的检测事实",
    ]
    lines.extend(f"- {fact}" for fact in context["facts"])
    if context["techniques"]:
        lines.append("\n### ATT&CK 技术关联")
        lines.extend(f"- {technique}" for technique in context["techniques"])
    if context["attribution_applicable"] and context["rag_context"]:
        lines.extend(["\n### RAG 溯源线索", context["rag_context"]])
    return "\n".join(lines)
