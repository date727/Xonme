"""
归因分析 Prompt 模板
用于 LLM 的威胁溯源归因推理
"""


ATTRIBUTION_SYSTEM_PROMPT = """你是一名资深的网络安全威胁情报分析专家，专注于 APT 组织溯源归因。

你的专长包括：
- 深入理解 MITRE ATT&CK 框架和 APT 组织的 TTP（战术、技术、流程）
- 分析网络流量特征并将其映射到已知威胁行为模式
- 基于多维证据进行归因推理，评估置信度
- 生成结构化、可操作的威胁情报报告

你的分析原则：
1. 基于证据：所有结论必须有具体技术证据支持
2. 客观评估：诚实说明不确定性，避免过度归因
3. 多维分析：综合考虑技术特征、行为模式、历史活动
4. 实用导向：提供可操作的防御建议和 IOC
"""


ATTRIBUTION_ANALYSIS_PROMPT = """请对以下威胁进行深度归因分析。

## 检测到的威胁信号

{threat_signals}

## RAG 知识库检索结果

基于向量相似度检索，以下 APT 组织与本次检测高度相关：

{rag_candidates}

## 分析任务

请完成以下分析（以 Markdown 格式输出）：

### 1. 归因判断
- 判断该威胁**最可能归属于哪个 APT 组织**
- 给出置信度（0-100%），并解释置信度的依据
- 如果置信度较低（<60%），说明原因和替代假设

### 2. 关键证据分析
列出**支持此归因判断的 3-5 条关键证据**，每条证据需包括：
- 观察到的技术特征
- 与目标组织已知 TTP 的匹配点
- 证据强度评估（强/中/弱）

如果有**反对证据**（与目标组织行为不符），也需要列出并解释。

### 3. MITRE ATT&CK 技术映射
- 列出本次威胁使用的 MITRE ATT&CK 技术编号和名称
- 解释这些技术如何体现在检测的特征中
- 标注哪些技术是该 APT 组织的**典型手法**

### 4. 威胁上下文分析
- 该 APT 组织的典型目标行业/地区
- 常用的攻击链阶段（C2 是哪个阶段）
- 可能的攻击动机（间谍活动、经济利益、破坏等）

### 5. 防御建议
提供 3-5 条具体的防御和检测建议，包括：
- 网络层防御（防火墙规则、流量监控）
- 主机层防御（EDR 规则、进程监控）
- 检测规则（Sigma/Yara/Snort 规则描述）
- IOC 提取（IP/域名/JA3 指纹）

### 6. 不确定性和替代假设
- 说明分析中的不确定因素
- 如果有其他可能的归因目标，列出并说明为何排除
- 需要进一步收集的情报（如果有）

## 输出要求
- 使用 Markdown 格式，结构清晰
- 技术术语准确，引用 MITRE ATT&CK 技术时包含编号
- 结论明确，但诚实说明局限性
- 避免过度推测，所有判断需有证据支持
"""


ATTRIBUTION_BRIEF_PROMPT = """请对以下威胁进行简要归因分析（2-3 段文字）。

## 检测到的威胁信号
{threat_signals}

## RAG 检索结果
{rag_candidates}

## 输出要求
1. **第一段**：归因结论（最可能的组织 + 置信度 + 主要依据）
2. **第二段**：关键证据（2-3 条技术特征与 TTP 的匹配）
3. **第三段**：防御建议（2-3 条实用建议）

使用 Markdown 格式，简洁专业。
"""


def format_threat_signals(threat_feature: dict) -> str:
    """
    格式化威胁信号为 LLM 输入
    
    Args:
        threat_feature: 威胁特征字典
    
    Returns:
        格式化的文本
    """
    lines = []
    
    # 基础信息
    lines.append(f"**通信端点**: {threat_feature['src_ip']} → {threat_feature['dst_ip']}:{threat_feature['dst_port']}")
    
    # RITA 评分
    if threat_feature.get("beacon_score", 0) > 0:
        lines.append(f"**Beacon 评分**: {threat_feature['beacon_score']:.0f}/100 (RITA 检测)")
    
    if threat_feature.get("long_conn_value", 0) > 0:
        hours = threat_feature["long_conn_value"] / 3600
        lines.append(f"**连接持续时间**: {hours:.1f} 小时")
    
    if threat_feature.get("c2_over_dns_value", 0) > 0:
        lines.append(f"**DNS 子域名数量**: {threat_feature['c2_over_dns_value']:.0f}（疑似 DGA）")
    
    lines.append(f"**威胁级别**: {threat_feature.get('threat_category', 'unknown').upper()}")
    
    # 连接行为
    lines.append(f"\n**连接行为**:")
    lines.append(f"- 连接次数: {threat_feature.get('conn_count', 0)}")
    lines.append(f"- 平均间隔: {threat_feature.get('avg_interval', 0):.1f} 秒")
    lines.append(f"- 总传输: {threat_feature.get('total_bytes', 0):,} 字节")
    
    # TLS 特征
    if threat_feature.get("tls_ja3"):
        lines.append(f"\n**TLS 加密特征**:")
        lines.append(f"- JA3 指纹: `{threat_feature['tls_ja3']}`")
        if threat_feature.get("tls_cipher"):
            lines.append(f"- 加密套件: {threat_feature['tls_cipher']}")
        if threat_feature.get("tls_server_name"):
            lines.append(f"- 服务器名称: {threat_feature['tls_server_name']}")
    
    # DNS 查询
    if threat_feature.get("dns_queries"):
        lines.append(f"\n**DNS 查询记录**:")
        for query in threat_feature["dns_queries"][:5]:
            lines.append(f"- {query}")
    
    # HTTP 特征
    if threat_feature.get("http_user_agents"):
        lines.append(f"\n**HTTP 特征**:")
        lines.append(f"- User-Agent: {threat_feature['http_user_agents'][0]}")
    
    if threat_feature.get("http_uris"):
        lines.append(f"- URI 路径: {', '.join(threat_feature['http_uris'][:3])}")
    
    return "\n".join(lines)


def format_rag_candidates(candidates: list[dict], top_n: int = 3) -> str:
    """
    格式化 RAG 候选结果为 LLM 输入
    
    Args:
        candidates: RAG 检索候选列表
        top_n: 显示前 N 个候选
    
    Returns:
        格式化的文本
    """
    if not candidates:
        return "未找到匹配的 APT 组织"
    
    lines = []
    
    for i, candidate in enumerate(candidates[:top_n], 1):
        lines.append(f"### 候选 {i}: {candidate['name']}")
        lines.append(f"**向量相似度**: {candidate['score']:.3f}")
        
        # 别名
        aliases = candidate["metadata"].get("aliases", [])
        if aliases:
            lines.append(f"**已知别名**: {', '.join(aliases)}")
        
        # C2 技术
        c2_techniques = candidate["metadata"].get("c2_techniques", [])
        if c2_techniques:
            lines.append(f"**使用的 C2 技术**: {', '.join(c2_techniques[:8])}")
        
        # 组织描述（截取前 300 字符）
        text = candidate.get("text", "")
        if text:
            description = text.split("\n组织描述:\n")[-1].split("\n使用的 C2")[0]
            lines.append(f"**组织描述**: {description[:300]}...")
        
        lines.append(f"**MITRE 参考**: {candidate['metadata']['mitre_url']}")
        lines.append("")
    
    return "\n".join(lines)


def create_attribution_prompt(
    threat_feature: dict,
    rag_candidates: list[dict],
    mode: str = "full"
) -> dict:
    """
    创建归因分析 Prompt
    
    Args:
        threat_feature: 威胁特征
        rag_candidates: RAG 检索结果
        mode: "full" 完整分析 或 "brief" 简要分析
    
    Returns:
        包含 system 和 user prompt 的字典
    """
    threat_signals = format_threat_signals(threat_feature)
    candidates_text = format_rag_candidates(rag_candidates, top_n=3)
    
    if mode == "brief":
        user_prompt = ATTRIBUTION_BRIEF_PROMPT.format(
            threat_signals=threat_signals,
            rag_candidates=candidates_text
        )
    else:
        user_prompt = ATTRIBUTION_ANALYSIS_PROMPT.format(
            threat_signals=threat_signals,
            rag_candidates=candidates_text
        )
    
    return {
        "system": ATTRIBUTION_SYSTEM_PROMPT,
        "user": user_prompt,
    }


def main():
    """测试 Prompt 生成"""
    # 模拟威胁特征
    test_feature = {
        "src_ip": "10.0.1.100",
        "dst_ip": "203.0.113.50",
        "dst_port": "443",
        "beacon_score": 95,
        "long_conn_value": 25200,
        "c2_over_dns_value": 0,
        "threat_category": "high",
        "conn_count": 420,
        "avg_interval": 60.2,
        "total_bytes": 5242880,
        "tls_ja3": "771,49195-49199-49196-49200-52393-52392",
        "tls_cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "tls_server_name": "update.example.com",
        "dns_queries": ["update.example.com"],
        "http_user_agents": [],
        "http_uris": [],
    }
    
    # 模拟 RAG 候选
    test_candidates = [
        {
            "name": "APT29",
            "score": 0.756,
            "metadata": {
                "aliases": ["Cozy Bear", "The Dukes"],
                "c2_techniques": ["T1071.001", "T1573.002", "T1571"],
                "mitre_url": "https://attack.mitre.org/groups/G0016/",
            },
            "text": "组织描述:\nAPT29 is a sophisticated threat group...",
        },
        {
            "name": "APT28",
            "score": 0.682,
            "metadata": {
                "aliases": ["Fancy Bear"],
                "c2_techniques": ["T1071.001", "T1090"],
                "mitre_url": "https://attack.mitre.org/groups/G0007/",
            },
            "text": "组织描述:\nAPT28 is a threat group...",
        },
    ]
    
    # 生成完整 Prompt
    print("=" * 70)
    print("完整分析 Prompt")
    print("=" * 70)
    prompt = create_attribution_prompt(test_feature, test_candidates, mode="full")
    print(f"\nSystem Prompt 长度: {len(prompt['system'])} 字符")
    print(f"User Prompt 长度: {len(prompt['user'])} 字符")
    print(f"\n--- User Prompt 预览 ---")
    print(prompt['user'][:500])
    print("...\n")
    
    # 生成简要 Prompt
    print("=" * 70)
    print("简要分析 Prompt")
    print("=" * 70)
    brief_prompt = create_attribution_prompt(test_feature, test_candidates, mode="brief")
    print(f"\nUser Prompt 长度: {len(brief_prompt['user'])} 字符")
    print(f"\n--- User Prompt ---")
    print(brief_prompt['user'])


if __name__ == "__main__":
    main()
