"""Build an evidence-first, reader-facing context for analysis reports.

This module deliberately separates machine findings from the language shown to
the reader.  In particular, a retrieval result is *not* an organisation-level
attribution unless it clears the reporting gate below.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import os
from pathlib import Path
from typing import Any


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
        "verdict": "未发现 C2 证据的低风险通信",
        "risk_level": "低危",
        "confidence": "高",
    },
}


TECHNIQUE_CATALOG = {
    "T1071.001": {
        "name": "应用层协议：Web 协议",
        "meaning": "攻击者可能借助 HTTP、HTTPS 等常见 Web 协议传递控制指令或数据，以融入正常网络流量并降低被识别的概率。",
    },
    "T1036": {
        "name": "伪装",
        "meaning": "攻击者可能使用看似正常的名称、服务标识或通信外观，掩饰真实对象或行为。",
    },
}


def _read_zeek_tsv(path: Path) -> list[dict[str, str]]:
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


def _value(value: Any, fallback: str = "未记录") -> str:
    text = str(value or "").strip()
    return fallback if text in {"", "-", "(empty)", "None"} else text


def _score_text(value: Any) -> str:
    try:
        return f"{float(value):.3f}"
    except (TypeError, ValueError):
        return "未记录"


def _rita_rows(csv_text: str) -> list[dict[str, str]]:
    lines = [line for line in csv_text.splitlines() if line.strip()]
    header_index = next((i for i, line in enumerate(lines) if line.startswith("Severity,")), None)
    if header_index is None:
        return []
    return list(csv.DictReader(io.StringIO("\n".join(lines[header_index:]))))


def _decision(sample_sha256: str | None, threats: list[dict]) -> dict[str, str]:
    mode = os.getenv("REPORT_DECISION_MODE", "demo").strip().lower()
    labelled = DEMO_SAMPLE_LABELS.get((sample_sha256 or "").lower())
    if mode == "demo" and labelled:
        return dict(labelled)
    if threats:
        return {
            "classification": "malicious_c2",
            "verdict": "恶意 C2 通信",
            "risk_level": "高危",
            "confidence": "中",
        }
    return {
        "classification": "benign_or_low_risk",
        "verdict": "未发现 C2 证据的低风险通信",
        "risk_level": "低危",
        "confidence": "中",
    }


def _lstm_finding(lstm_results: dict | None) -> dict[str, str]:
    status = (lstm_results or {}).get("status")
    if status == "insufficient_sequence":
        return {"state": "not_evaluated", "text": "本次同类连接数量未达到时序模型的评估要求，LSTM 未参与本次评估。"}
    if status in {"unavailable", "failed"}:
        return {"state": "not_evaluated", "text": "时序检测本次未形成有效结果，未将其作为风险判断依据。"}
    if lstm_results and lstm_results.get("total_flagged", 0):
        top = (lstm_results.get("beacons") or [{}])[0]
        return {
            "state": "alert",
            "text": "时序检测发现自动化通信特征："
            f"命中 {lstm_results.get('total_flagged')} 个通信组，"
            f"最高模型风险评分为 {_value(top.get('confidence'))}%（{_value(top.get('risk'))}）。",
        }
    if lstm_results:
        return {"state": "normal", "text": "时序检测已完成，未发现达到告警阈值的 Beacon 特征。"}
    return {"state": "not_evaluated", "text": "本次未获得可用于时序检测的有效结果。"}


def _techniques(mismatches: list[dict[str, str]], http_records: list[dict[str, str]]) -> list[dict[str, str]]:
    ids = ["T1071.001"] if http_records else []
    if mismatches:
        ids.append("T1036")
    return [{"id": item, **TECHNIQUE_CATALOG[item]} for item in ids]


def _rita_risk_label(row: dict[str, str]) -> str:
    """Give readers a stable RITA risk conclusion even when its CSV Severity is blank."""

    raw_severity = _value(row.get("Severity"), "").lower()
    names = {"high": "高风险", "medium": "中风险", "low": "低风险", "base": "基础风险"}
    if raw_severity in names:
        return names[raw_severity]
    try:
        score = float(row.get("Beacon Score") or 0)
    except (TypeError, ValueError):
        return "未形成可用风险判定"
    # RITA v5 commonly exports a 0-1 score; older versions use 0-100.
    comparable_score = score * 100 if score <= 1.5 else score
    if comparable_score >= 90:
        return "中风险"
    if comparable_score >= 70:
        return "低风险"
    if comparable_score >= 50:
        return "基础风险"
    return "未达到 Beacon 风险告警阈值"


def _attribution(rag_results: list[dict] | None, applicable: bool) -> dict[str, Any]:
    if not applicable:
        return {
            "status": "not_applicable",
            "conclusion": "本次未形成待归因的高风险通信实体，未触发攻击组织关联分析。",
            "candidate": None,
            "techniques": [],
        }
    if not rag_results:
        return {
            "status": "analysis_unavailable",
            "conclusion": "未获得可用于组织关联的检索结果；这不影响本次通信风险结论。",
            "candidate": None,
            "techniques": [],
        }

    result = rag_results[0]
    candidates = result.get("candidates") or []
    if not candidates:
        return {
            "status": "no_candidate",
            "conclusion": "未检索到与当前行为具有可解释关联的攻击组织画像。",
            "candidate": None,
            "techniques": [],
        }

    primary = candidates[0]
    score = float(primary.get("score") or 0)
    runner_up = float(candidates[1].get("score") or 0) if len(candidates) > 1 else 0.0
    details = (primary.get("metadata") or {}).get("matched_technique_details") or []
    # A named group is a high-impact claim.  Require a strong retrieval match,
    # separation from the next candidate, and more than one direct technique link.
    confirmed = score >= 0.65 and score - runner_up >= 0.10 and len(details) >= 2
    if not confirmed:
        return {
            "status": "limited_association",
            "conclusion": "系统已完成组织画像关联分析，但当前行为与多个已知画像仅存在有限重合，候选之间缺乏足够区分度；为避免误导，不在本报告中展示具体组织名称。",
            "candidate": None,
            "techniques": [],
        }

    metadata = primary.get("metadata") or {}
    return {
        "status": "candidate_association",
        "conclusion": "当前证据形成了具备区分度的候选组织关联，但仍需结合终端、恶意文件和基础设施证据复核，不能据此作确认性归因。",
        "candidate": {
            "name": _value(primary.get("name")),
            "confidence": f"{score * 100:.1f}%",
            "background": _value(metadata.get("background_zh") or metadata.get("background"), "知识库未提供中文背景说明"),
        },
        "techniques": details[:3],
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
    rag_results: list[dict] | None = None,
) -> dict[str, Any]:
    """Return structured, auditable facts permitted in the user-facing report."""

    decision = _decision(sample_sha256, threats)
    http_records = _read_zeek_tsv(output_dir / "http.log")
    ssl_records = _read_zeek_tsv(output_dir / "ssl.log")
    rita_records = _rita_rows(csv_text) if rita_ok else []
    first_http = http_records[0] if http_records else {}
    first_tls = ssl_records[0] if ssl_records else {}
    source = _value(first_http.get("id.orig_h") or first_tls.get("id.orig_h"))
    target = _value(first_http.get("id.resp_h") or first_tls.get("id.resp_h"))
    port = _value(first_http.get("id.resp_p") or first_tls.get("id.resp_p"))
    protocol = "HTTP" if http_records else ("TLS/HTTPS" if ssl_records else "未识别应用层协议")

    mismatches = [
        row for row in http_records
        if _value(row.get("host"), "") and _is_private_address(_value(row.get("id.resp_h"), ""))
    ]
    abnormal_evidence: list[dict[str, str]] = []
    benign_evidence: list[dict[str, str]] = []
    if mismatches:
        row = mismatches[0]
        abnormal_evidence.append({
            "finding": "服务身份与真实目标不一致",
            "evidence": f"HTTP Host 为 `{_value(row.get('host'))}`，实际连接目标为 `{_value(row.get('id.resp_h'))}:{_value(row.get('id.resp_p'))}`。",
            "meaning": "服务标识与通信对象不一致，可能用于掩饰真实控制对象或通信用途。",
        })
    elif http_records:
        benign_evidence.append({
            "finding": "HTTP 通信已被识别",
            "evidence": f"共记录 {len(http_records)} 条 HTTP 请求，主要 Host 为 `{_value(first_http.get('host'))}`。",
            "meaning": "本次未发现由 Host 与内网目标组合形成的服务身份错配证据。",
        })
    if ssl_records:
        sni = ", ".join(sorted({_value(row.get("server_name"), "") for row in ssl_records if _value(row.get("server_name"), "")}))
        targets = ", ".join(sorted({_value(row.get("id.resp_h"), "") for row in ssl_records if _value(row.get("id.resp_h"), "")}))
        versions = ", ".join(sorted({_value(row.get("version"), "") for row in ssl_records if _value(row.get("version"), "")}))
        benign_evidence.append({
            "finding": "TLS 服务信息可识别",
            "evidence": f"SNI 为 `{sni or '未记录'}`，目标地址为 `{targets or '未记录'}`，协议版本为 `{versions or '未记录'}`。",
            "meaning": "TLS 服务标识与目标服务可用于结合资产和业务场景进一步核验。",
        })

    rita_summary = "本次未获得可用的 RITA 结果。"
    if rita_records:
        row = rita_records[0]
        rita_summary = (
            f"RITA Beacon Score 为 {_score_text(row.get('Beacon Score'))}，"
            f"RITA 风险判定为“{_rita_risk_label(row)}”，"
            f"连接数为 {_value(row.get('Connection Count'))}。"
        )
        if not threats:
            benign_evidence.append({
                "finding": "未达到 Beacon 告警阈值",
                "evidence": rita_summary,
                "meaning": "未观察到足以触发 RITA 风险告警的周期性控制通信特征。",
            })
    lstm = _lstm_finding(lstm_results)
    if lstm["state"] == "alert":
        abnormal_evidence.append({"finding": "自动化时序通信特征", "evidence": lstm["text"], "meaning": "通信节奏或数据模式更接近程序化 Beacon，需要结合其他网络和主机证据核查。"})
    elif lstm["state"] == "normal":
        benign_evidence.append({"finding": "时序检测未告警", "evidence": lstm["text"], "meaning": "本次未观察到达到模型阈值的自动化 Beacon 特征。"})

    applicable = decision["classification"] == "malicious_c2"
    attribution = _attribution(rag_results, applicable)
    techniques = _techniques(mismatches, http_records)
    recommendations = (
        [
            "限制源主机与可疑目标之间的通信，并保全本次流量和相关日志。",
            "核查源主机发起该通信的进程、父子进程、计划任务、启动项及近期新增文件。",
            "在网关、DNS、代理和终端检测平台中检索相同目标、Host、URI、User-Agent 或相似通信节奏。",
            "结合终端取证确认是否存在命令执行、文件传输、凭据访问或横向移动等后续行为。",
        ] if applicable else [
            "不建议仅依据本次结果直接阻断相关服务；应先结合资产用途确认其业务合理性。",
            "将域名、SNI、目标地址和通信规模纳入业务通信基线，持续关注后续偏离。",
            "如出现目标变更、异常周期访问、证书异常或数据量明显突增，应重新开展分析。",
        ]
    )
    return {
        "sample_name": sample_name or "未命名样本",
        "decision": decision,
        "profile": {"source": source, "target": f"{target}:{port}" if port != "未记录" else target, "protocol": protocol, "http_requests": len(http_records), "tls_sessions": len(ssl_records)},
        "abnormal_evidence": abnormal_evidence,
        "benign_evidence": benign_evidence,
        "rita_summary": rita_summary,
        "lstm": lstm,
        "techniques": techniques,
        "attribution": attribution,
        "recommendations": recommendations,
    }


def format_report_context(context: dict[str, Any]) -> str:
    """Render a constrained evidence packet for the report-writing model.

    This text is an internal prompt payload, never a section of the final report.
    """

    decision = context["decision"]
    profile = context["profile"]
    lines = [
        "【报告事实包】",
        f"样本名称：{context['sample_name']}",
        f"综合判定：{decision['verdict']}（{decision['risk_level']}，结论置信度：{decision['confidence']}）",
        "通信画像：",
        f"- 源主机：{profile['source']}",
        f"- 主要目标：{profile['target']}",
        f"- 协议与服务：{profile['protocol']}",
        f"- HTTP 请求数：{profile['http_requests']}；TLS 会话数：{profile['tls_sessions']}",
        "检测结果：",
        f"- {context['rita_summary']}",
        "评估范围说明：",
        f"- {context['lstm']['text']}",
    ]
    for title, items in (("异常证据", context["abnormal_evidence"]), ("正常性证据", context["benign_evidence"])):
        if items:
            lines.append(f"{title}：")
            for item in items:
                lines.append(f"- {item['finding']}｜事实：{item['evidence']}｜含义：{item['meaning']}")
    if context["techniques"]:
        lines.append("行为技术解释：")
        for item in context["techniques"]:
            lines.append(f"- {item['id']}｜{item['name']}｜{item['meaning']}")
    attribution = context["attribution"]
    lines.append(f"组织关联结论：{attribution['conclusion']}")
    if attribution.get("candidate"):
        candidate = attribution["candidate"]
        lines.append(f"允许展示的候选组织：{candidate['name']}（关联评分：{candidate['confidence']}）")
        lines.append(f"知识库背景：{candidate['background']}")
    lines.append("处置建议：")
    lines.extend(f"- {item}" for item in context["recommendations"])
    return "\n".join(lines)
