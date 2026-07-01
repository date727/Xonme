"""
RAG 检索引擎
整合威胁特征提取和向量知识库检索，实现智能归因
"""

from pathlib import Path
from typing import Any


DEFAULT_KB_PATH = Path(__file__).resolve().parent.parent / "chroma_db"

try:
    from app.knowledge_base import VectorKnowledgeBase
    from app.data_extractor import ThreatFeatureExtractor
    from app.feature_encoder import encode_threat_signal, encode_for_rag_query
    KB_AVAILABLE = True
except ImportError:
    KB_AVAILABLE = False


class ThreatAttributionEngine:
    """威胁归因引擎 - 基于 RAG 的 APT 组织检索"""
    
    def __init__(
        self,
        kb_path: str | Path = DEFAULT_KB_PATH,
        top_k: int = 5,
    ):
        """
        初始化归因引擎
        
        Args:
            kb_path: 向量知识库路径
            top_k: 返回候选 APT 组织数量
        """
        if not KB_AVAILABLE:
            raise ImportError(
                "知识库模块未安装。请先运行:\n"
                "pip install chromadb sentence-transformers\n"
                "python build_knowledge_base.py"
            )
        
        resolved_kb_path = Path(kb_path)
        self.kb = VectorKnowledgeBase(db_path=resolved_kb_path)
        self.top_k = top_k
        
        # 验证知识库
        stats = self.kb.get_stats()
        if stats["document_count"] == 0:
            raise ValueError(
                f"知识库为空！请先构建知识库:\n"
                f"python build_knowledge_base.py\n"
                f"当前路径: {resolved_kb_path}"
            )
        
        print(f"✓ 威胁归因引擎初始化完成")
        print(f"  - 知识库: {stats['document_count']} 个 APT 组织")
        print(f"  - 检索 Top-{top_k} 候选")
    
    def attribute_single_threat(self, threat_feature: dict) -> dict:
        """
        对单个威胁特征进行归因
        
        Args:
            threat_feature: 威胁特征字典（来自 ThreatFeatureExtractor）
        
        Returns:
            归因结果字典
        """
        # 生成 RAG 查询
        query = encode_for_rag_query(threat_feature)
        
        # 检索相似 APT 组织
        candidates = self.kb.search(query, top_k=self.top_k)
        
        # 构建归因结果
        result = {
            "threat_feature": threat_feature,
            "query": query,
            "candidates": candidates,
            "primary_candidate": candidates[0] if candidates else None,
            "confidence": self._calculate_confidence(candidates),
            "matched_techniques": self._extract_matched_techniques(threat_feature, candidates),
        }
        
        return result
    
    def attribute_multiple_threats(self, threat_features: list[dict]) -> list[dict]:
        """
        批量归因
        
        Args:
            threat_features: 威胁特征列表
        
        Returns:
            归因结果列表
        """
        results = []
        
        for i, feature in enumerate(threat_features, 1):
            print(f"正在归因威胁 {i}/{len(threat_features)}...")
            result = self.attribute_single_threat(feature)
            results.append(result)
        
        return results
    
    def _calculate_confidence(self, candidates: list[dict]) -> float:
        """
        计算归因置信度
        
        基于以下因素：
        1. Top-1 候选的相似度分数
        2. Top-1 与 Top-2 的分数差距（差距越大越可信）
        3. 候选组织的 C2 技术数量
        
        Returns:
            置信度 0-100
        """
        if not candidates:
            return 0.0
        
        top1 = candidates[0]
        top1_score = top1["score"]
        
        # 基础置信度：相似度分数
        base_confidence = top1_score * 100
        
        # 如果有第二候选，考虑分数差距
        if len(candidates) > 1:
            top2_score = candidates[1]["score"]
            score_gap = top1_score - top2_score
            
            # 差距越大，置信度越高（最多加 20 分）
            gap_bonus = min(score_gap * 100, 20)
            base_confidence += gap_bonus
        
        # 限制在 0-100 范围
        return min(max(base_confidence, 0), 100)
    
    def _extract_matched_techniques(
        self, 
        threat_feature: dict, 
        candidates: list[dict]
    ) -> list[str]:
        """
        提取匹配的 MITRE ATT&CK 技术
        
        Returns:
            技术 ID 列表（如 ["T1071.001", "T1573.002"]）
        """
        if not candidates:
            return []
        
        # 从 Top-1 候选提取 C2 技术
        top1 = candidates[0]
        techniques = top1["metadata"].get("c2_techniques", [])
        
        # 根据威胁特征进一步筛选
        matched = []
        
        # Beacon 通信 → T1071.* 或 T1573.*
        if threat_feature.get("beacon_score", 0) >= 90:
            matched.extend([t for t in techniques if t.startswith(("T1071", "T1573"))])
        
        # DNS 隧道 → T1071.004
        if threat_feature.get("c2_over_dns_value", 0) >= 800:
            matched.extend([t for t in techniques if t == "T1071.004"])
        
        # 长连接 → T1571
        if threat_feature.get("long_conn_value", 0) >= 28800:
            matched.extend([t for t in techniques if t == "T1571"])
        
        # 非标准端口
        port = threat_feature.get("dst_port", "")
        if port and port not in ["80", "443", "53"]:
            matched.extend([t for t in techniques if t == "T1571"])
        
        # TLS 加密 → T1573.*
        if threat_feature.get("tls_ja3"):
            matched.extend([t for t in techniques if t.startswith("T1573")])
        
        # 去重并返回
        return list(set(matched)) if matched else techniques[:5]
    
    def generate_attribution_report(self, attribution_result: dict) -> str:
        """
        生成人类可读的归因报告（Markdown 格式）
        
        Args:
            attribution_result: 归因结果字典
        
        Returns:
            Markdown 格式的报告文本
        """
        feature = attribution_result["threat_feature"]
        candidates = attribution_result["candidates"]
        primary = attribution_result["primary_candidate"]
        confidence = attribution_result["confidence"]
        techniques = attribution_result["matched_techniques"]
        
        # 构建报告
        lines = ["# 威胁溯源归因报告\n"]
        
        # 1. 威胁特征摘要
        lines.append("## 1. 检测到的威胁特征\n")
        lines.append(encode_threat_signal(feature))
        lines.append("\n")
        
        # 2. 归因结果
        lines.append("## 2. 归因分析\n")
        
        if not primary:
            lines.append("⚠️ **未找到匹配的 APT 组织**\n")
            return "\n".join(lines)
        
        lines.append(f"**最可能的归属组织**: {primary['name']}")
        lines.append(f"**置信度**: {confidence:.1f}%\n")
        
        # 别名
        aliases = primary["metadata"].get("aliases", [])
        if aliases:
            lines.append(f"**已知别名**: {', '.join(aliases)}\n")
        
        # 3. 匹配的 ATT&CK 技术
        if techniques:
            lines.append("## 3. 匹配的 MITRE ATT&CK 技术\n")
            for tech_id in techniques:
                tech_url = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
                lines.append(f"- [{tech_id}]({tech_url})")
            lines.append("\n")
        
        # 4. 关键证据
        lines.append("## 4. 支持归因的关键证据\n")
        
        evidence = []
        
        # Beacon 特征
        if feature.get("beacon_score", 0) >= 90:
            evidence.append(
                f"- **周期性通信**: Beacon 评分 {feature['beacon_score']:.0f}/100，"
                f"平均间隔 {feature.get('avg_interval', 0):.1f} 秒"
            )
        
        # TLS 指纹
        if feature.get("tls_ja3"):
            evidence.append(
                f"- **TLS 指纹**: JA3={feature['tls_ja3'][:40]}..."
            )
            if feature.get("tls_cipher"):
                evidence.append(f"  - 加密套件: {feature['tls_cipher']}")
        
        # DNS 行为
        if feature.get("c2_over_dns_value", 0) >= 800:
            evidence.append(
                f"- **DNS 隧道**: 检测到 {feature['c2_over_dns_value']:.0f} 个子域名（疑似 DGA）"
            )
        
        # 长连接
        if feature.get("long_conn_value", 0) >= 28800:
            hours = feature["long_conn_value"] / 3600
            evidence.append(f"- **持久化连接**: 连接持续 {hours:.1f} 小时")
        
        # 非标准端口
        port = feature.get("dst_port", "")
        if port and port not in ["80", "443", "53"]:
            evidence.append(f"- **非标准端口**: 使用端口 {port}")
        
        lines.extend(evidence)
        lines.append("\n")
        
        # 5. 其他候选组织
        if len(candidates) > 1:
            lines.append("## 5. 其他可能的候选组织\n")
            for i, candidate in enumerate(candidates[1:4], 2):  # Top 2-4
                lines.append(
                    f"{i}. **{candidate['name']}** "
                    f"(相似度: {candidate['score']:.3f})"
                )
            lines.append("\n")
        
        # 6. 参考资源
        lines.append("## 6. 参考资源\n")
        lines.append(f"- [MITRE ATT&CK: {primary['name']}]({primary['metadata']['mitre_url']})")
        lines.append(f"- 该组织使用了 {primary['metadata']['c2_technique_count']} 个 C2 相关技术")
        
        return "\n".join(lines)


def main():
    """测试脚本"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python rag_engine.py <rita_csv_file> <zeek_log_dir>")
        sys.exit(1)
    
    rita_csv_path = Path(sys.argv[1])
    zeek_log_dir = Path(sys.argv[2])
    
    # 1. 提取威胁特征
    print("=== 步骤 1: 提取威胁特征 ===")
    with open(rita_csv_path, "r", encoding="utf-8") as f:
        rita_csv = f.read()
    
    extractor = ThreatFeatureExtractor(rita_csv, zeek_log_dir)
    features = extractor.extract_all()
    
    if not features:
        print("未检测到高危威胁")
        sys.exit(0)
    
    # 2. 初始化归因引擎
    print("\n=== 步骤 2: 初始化归因引擎 ===")
    engine = ThreatAttributionEngine(kb_path="./chroma_db", top_k=5)
    
    # 3. 执行归因
    print("\n=== 步骤 3: 执行归因分析 ===")
    results = engine.attribute_multiple_threats(features)
    
    # 4. 生成报告
    print("\n=== 步骤 4: 生成归因报告 ===")
    for i, result in enumerate(results, 1):
        report = engine.generate_attribution_report(result)
        
        # 保存报告
        report_path = Path(f"attribution_report_{i}.md")
        report_path.write_text(report, encoding="utf-8")
        
        print(f"\n报告 {i} 已保存到: {report_path}")
        print(f"归因结果: {result['primary_candidate']['name'] if result['primary_candidate'] else 'Unknown'}")
        print(f"置信度: {result['confidence']:.1f}%")


if __name__ == "__main__":
    main()
