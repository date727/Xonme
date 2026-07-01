"""
特征编码器
将 RITA 和 LSTM 检测结果转换为自然语言描述，用于 RAG 检索

注意：当前版本只使用 RITA 和 LSTM 的检测结果，不包含 Zeek 原始日志的详细信息。
"""


def encode_threat_signal(feature: dict) -> str:
    """
    将威胁特征编码为自然语言描述
    
    Args:
        feature: 威胁特征字典（包含 RITA + LSTM 检测结果）
    
    Returns:
        自然语言描述文本
    """
    parts = []
    
    # 基础连接信息
    parts.append(f"检测到疑似 C2 通信：")
    parts.append(f"源 IP: {feature['src_ip']} → 目标 IP: {feature['dst_ip']}:{feature['dst_port']}")
    
    # RITA 检测评分
    scores = []
    if feature.get("beacon_score", 0) > 0:
        scores.append(f"Beacon 评分 {feature['beacon_score']:.0f}/100")
    if feature.get("long_conn_value", 0) > 0:
        scores.append(f"长连接时长 {feature['long_conn_value']:.0f}秒")
    if feature.get("c2_over_dns_value", 0) > 0:
        scores.append(f"DNS 子域名数 {feature['c2_over_dns_value']:.0f}")
    
    if scores:
        parts.append(f"威胁评分: {', '.join(scores)}")
        parts.append(f"威胁级别: {feature.get('threat_category', 'unknown').upper()}")
    
    # 连接行为特征
    if feature.get("conn_count", 0) > 0:
        parts.append(
            f"连接行为: {feature['conn_count']} 次连接, "
            f"平均间隔 {feature.get('avg_interval', 0):.1f} 秒, "
            f"总传输 {feature.get('total_bytes', 0)} 字节"
        )
    
    # TLS 加密特征
    if feature.get("tls_ja3"):
        parts.append(f"TLS 指纹: JA3={feature['tls_ja3'][:32]}...")
        if feature.get("tls_cipher"):
            parts.append(f"加密套件: {feature['tls_cipher']}")
        if feature.get("tls_server_name"):
            parts.append(f"服务器名称: {feature['tls_server_name']}")
    
    # DNS 行为
    if feature.get("dns_queries"):
        dns_list = feature["dns_queries"][:5]  # 限制数量
        parts.append(f"DNS 查询: {', '.join(dns_list)}")
    
    # HTTP 特征
    if feature.get("http_user_agents"):
        ua_list = feature["http_user_agents"][:3]
        parts.append(f"User-Agent: {', '.join(ua_list)}")
    
    if feature.get("http_uris"):
        uri_list = feature["http_uris"][:3]
        parts.append(f"HTTP URI: {', '.join(uri_list)}")
    
    return "\n".join(parts)


def encode_multiple_threats(features: list[dict], top_n: int = 5) -> str:
    """
    编码多个威胁特征
    
    Args:
        features: 威胁特征列表
        top_n: 只编码前 N 个（按威胁评分排序）
    
    Returns:
        自然语言描述文本
    """
    if not features:
        return "未检测到高危威胁"
    
    # 按 beacon_score 排序
    sorted_features = sorted(
        features,
        key=lambda x: x.get("beacon_score", 0),
        reverse=True
    )
    
    parts = [f"共检测到 {len(features)} 个疑似威胁，以下为 Top {min(top_n, len(features))}:\n"]
    
    for i, feature in enumerate(sorted_features[:top_n], 1):
        parts.append(f"--- 威胁 {i} ---")
        parts.append(encode_threat_signal(feature))
        parts.append("")
    
    return "\n".join(parts)


def encode_for_rag_query(feature: dict) -> str:
    """
    生成用于 RAG 检索的查询文本
    专注于 TTP 特征，忽略具体 IP 等细节
    
    Args:
        feature: 威胁特征字典
    
    Returns:
        RAG 查询文本
    """
    query_parts = []
    
    # 检测类型（使用 RITA 官方 "medium" 阈值）
    if feature.get("beacon_score", 0) >= 90:  # medium threshold
        query_parts.append("周期性 Beacon 通信")
    
    if feature.get("c2_over_dns_value", 0) >= 800:  # medium threshold  
        query_parts.append("DNS 隧道或 DGA 域名")
    
    if feature.get("long_conn_value", 0) >= 28800:  # 8 hours
        query_parts.append("持久化长连接")
    
    # TLS 加密
    if feature.get("tls_ja3"):
        query_parts.append("TLS 加密通道")
        if feature.get("tls_cipher"):
            query_parts.append(f"使用 {feature['tls_cipher']} 加密套件")
    
    # 端口特征
    port = feature.get("dst_port", "")
    if port and port not in ["80", "443", "53"]:
        query_parts.append(f"非标准端口 {port}")
    
    # DNS 特征
    if feature.get("dns_queries"):
        query_parts.append("包含 DNS 查询行为")
    
    # HTTP 特征
    if feature.get("http_user_agents"):
        query_parts.append("HTTP 协议通信")
    
    if not query_parts:
        query_parts.append("可疑网络通信")
    
    return "使用以下特征的 APT 组织: " + ", ".join(query_parts)


def main():
    """测试脚本"""
    # 模拟威胁特征
    test_feature = {
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "dst_port": "8443",
        "beacon_score": 92,  # RITA 0-100 分制
        "long_conn_value": 30000,  # 8.3 小时（秒）
        "c2_over_dns_value": 850,  # 子域名数量
        "threat_category": "medium",
        "conn_count": 147,
        "avg_interval": 60.5,
        "total_bytes": 1024000,
        "tls_ja3": "771,49195-49199-49196-49200-52393-52392-49171",
        "tls_cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "tls_server_name": "update.example.com",
        "dns_queries": ["update.example.com", "cdn.example.com"],
        "http_user_agents": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"],
        "http_uris": ["/api/v1/check", "/api/v1/update"],
    }
    
    print("=== 完整特征描述 ===")
    print(encode_threat_signal(test_feature))
    
    print("\n=== RAG 查询文本 ===")
    print(encode_for_rag_query(test_feature))
    
    print("\n=== 多威胁编码 ===")
    features = [test_feature, test_feature]
    print(encode_multiple_threats(features, top_n=2))


if __name__ == "__main__":
    main()
