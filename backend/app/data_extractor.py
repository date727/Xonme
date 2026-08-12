"""
数据提取器模块
从 RITA CSV 和 Zeek 日志中提取威胁特征，用于 RAG 检索和归因分析

威胁评分标准说明：
- RITA 使用分级评分系统（base/low/medium/high），不是 0-1 归一化评分
- Beacon Score: 0-100 分制，基于时间戳、数据大小、持续时间、直方图的加权平均
- Long Connection: 以秒为单位的连接持续时间
- C2 Over DNS: 子域名数量（DGA 检测）
- 阈值定义来自 RITA 官方默认配置: https://github.com/activecm/rita/blob/master/default_config.hjson
"""

import csv
from pathlib import Path
from typing import Any


class RITADataExtractor:
    """RITA CSV 数据提取器"""
    
    # RITA 官方威胁评分阈值（来自 default_config.hjson）
    # Beacon Score: 0-100 分制
    BEACON_THRESHOLDS = {
        "base": 50,    # 基线威胁
        "low": 70,     # 低威胁
        "medium": 90,  # 中等威胁
        "high": 100    # 高威胁
    }
    
    # Long Connection Score: 秒数
    LONG_CONN_THRESHOLDS = {
        "base": 3600,   # 1 小时
        "low": 14400,   # 4 小时
        "medium": 28800,  # 8 小时
        "high": 43200   # 12 小时
    }
    
    # C2 Over DNS Score: 子域名数量
    C2_DNS_THRESHOLDS = {
        "base": 100,
        "low": 500,
        "medium": 800,
        "high": 1000
    }
    
    # 提取高危连接的最低阈值（使用 "low" 级别以提高检测灵敏度）
    MIN_BEACON_SCORE = BEACON_THRESHOLDS["low"]  # 70 (降低以捕获更多威胁)
    MIN_LONG_CONN_DURATION = LONG_CONN_THRESHOLDS["low"]  # 4 小时
    MIN_C2_DNS_SUBDOMAIN_COUNT = C2_DNS_THRESHOLDS["low"]  # 500
    
    def __init__(self, csv_text: str):
        """
        初始化提取器
        
        Args:
            csv_text: RITA CSV 输出的原始文本
        """
        self.csv_text = csv_text
        self.rows: list[dict[str, str]] = []
        self.high_risk_connections: list[dict] = []
        
    def parse(self) -> None:
        """解析 RITA CSV 数据"""
        raw_lines = self.csv_text.strip().splitlines()

        # 跳过 RITA 文本前导行（例如 "Viewing database: ..."），定位真正的 CSV 头
        start_idx = 0
        for i, line in enumerate(raw_lines):
            stripped = line.strip()
            if stripped and "," in stripped:
                start_idx = i
                break

        lines = [ln for ln in raw_lines[start_idx:] if ln.strip()]
        
        if not lines:
            return
        
        # 解析 CSV（RITA 使用逗号分隔）
        reader = csv.DictReader(lines)
        parsed_rows = list(reader)

        # 统一列名风格，兼容 RITA v5 的 "Beacon Score"、"Source IP" 等字段
        self.rows = [self._normalize_row(row) for row in parsed_rows]
        
        print(f"✓ 解析了 {len(self.rows)} 条 RITA 记录")
    
    def extract_high_risk(self) -> list[dict]:
        """
        提取高危连接
        
        Returns:
            高危连接列表
        """
        if not self.rows:
            self.parse()
        
        self.high_risk_connections = []

        # RITA v5 的 Beacon Score 常见 0-1 归一化；旧逻辑按 0-100。
        # 这里自动识别并转换，避免阈值错配导致全量漏检。
        raw_beacon_scores = [
            self._safe_float(self._pick(row, "beacon_score", "score", "beacon") or "0")
            for row in self.rows
        ]
        max_beacon_score = max(raw_beacon_scores) if raw_beacon_scores else 0.0
        beacon_is_normalized = max_beacon_score <= 1.5
        
        for row in self.rows:
            severity = (self._pick(row, "severity") or "").strip().lower()

            # 提取评分字段（兼容多版本字段名）
            beacon_score = self._safe_float(
                self._pick(row, "beacon_score", "score", "beacon") or "0"
            )
            if beacon_is_normalized:
                beacon_score *= 100.0
            
            # Long connection: 可能是持续时间（秒）或评分
            long_conn_value = self._safe_float(
                self._pick(
                    row,
                    "long_conn_score",
                    "long_connection_score",
                    "duration",
                    "total_duration",
                )
                or "0"
            )
            
            # C2 over DNS: 可能是子域名数量或评分
            c2_dns_score = self._safe_float(
                self._pick(row, "c2_over_dns_score", "c2_dns_score") or "0"
            )
            subdomain_count = self._safe_float(
                self._pick(row, "subdomains", "subdomain_count") or "0"
            )
            if subdomain_count > 0:
                c2_dns_value = subdomain_count
            elif c2_dns_score <= 1.0:
                c2_dns_value = c2_dns_score * 1000.0
            else:
                c2_dns_value = c2_dns_score
            
            # 调试：打印每条记录的评分
            src_ip = self._pick(row, "src", "src_ip", "source", "source_ip") or "unknown"
            dst_ip = self._pick(row, "dst", "dst_ip", "destination", "destination_ip") or "unknown"
            print(f"  📊 [{src_ip} → {dst_ip}] "
                  f"severity={severity or 'none'}, "
                  f"beacon={beacon_score:.1f}, "
                  f"long_conn={long_conn_value:.1f}, "
                  f"c2_dns={c2_dns_value:.1f}, "
                  f"c2_dns_score_raw={c2_dns_score:.3f}, "
                  f"subdomain_count={subdomain_count:.0f}")
            
            # 判断是否为高危（满足任一条件）
            is_high_risk = (
                severity in {"high", "medium"} or
                beacon_score >= self.MIN_BEACON_SCORE or
                long_conn_value >= self.MIN_LONG_CONN_DURATION or
                c2_dns_value >= self.MIN_C2_DNS_SUBDOMAIN_COUNT or
                # 新增：任何 beacon_score > 0 的都视为潜在威胁
                (beacon_score > 0 and beacon_score >= self.BEACON_THRESHOLDS["base"]) or
                # 新增：任何 c2_dns_score > 0.5 的都视为潜在 DGA
                (c2_dns_score > 0 and c2_dns_score >= 0.5) or
                # 新增：subdomain_count 超过基线的也算
                (subdomain_count > 0 and subdomain_count >= self.C2_DNS_THRESHOLDS["base"])
            )
            
            if is_high_risk:
                # 调试：说明触发原因
                reasons = []
                if severity in {"high", "medium"}:
                    reasons.append(f"severity={severity}")
                if beacon_score >= self.MIN_BEACON_SCORE:
                    reasons.append(f"beacon≥{self.MIN_BEACON_SCORE}")
                if long_conn_value >= self.MIN_LONG_CONN_DURATION:
                    reasons.append(f"long_conn≥{self.MIN_LONG_CONN_DURATION}")
                if c2_dns_value >= self.MIN_C2_DNS_SUBDOMAIN_COUNT:
                    reasons.append(f"c2_dns≥{self.MIN_C2_DNS_SUBDOMAIN_COUNT}")
                if beacon_score > 0 and beacon_score >= self.BEACON_THRESHOLDS["base"]:
                    reasons.append(f"beacon≥base({self.BEACON_THRESHOLDS['base']})")
                if c2_dns_score > 0 and c2_dns_score >= 0.5:
                    reasons.append(f"c2_dns_score≥0.5")
                if subdomain_count > 0 and subdomain_count >= self.C2_DNS_THRESHOLDS["base"]:
                    reasons.append(f"subdomain≥{self.C2_DNS_THRESHOLDS['base']}")
                print(f"    ✓ 标记为高危: {', '.join(reasons)}")
                
                port_proto_service = self._pick(row, "port_proto_service") or ""
                dst_port = (
                    self._pick(row, "dst_port", "port")
                    or self._extract_port(port_proto_service)
                    or "unknown"
                )

                connection = {
                    "src_ip": self._pick(row, "src", "src_ip", "source", "source_ip") or "unknown",
                    "dst_ip": self._pick(row, "dst", "dst_ip", "destination", "destination_ip") or "unknown",
                    "dst_port": dst_port,
                    "beacon_score": beacon_score,
                    "long_conn_value": long_conn_value,
                    "c2_over_dns_value": c2_dns_value,
                    "ja3": self._pick(row, "ja3") or "",
                    "connection_count": self._safe_int(
                        self._pick(row, "connection_count", "count") or "0"
                    ),
                    "total_bytes": self._safe_int(self._pick(row, "total_bytes", "bytes") or "0"),
                    "threat_category": self._categorize_threat(
                        beacon_score, long_conn_value, c2_dns_value, severity
                    ),
                    "raw_row": row,  # 保留原始数据
                }
                self.high_risk_connections.append(connection)
        
        print(f"✓ 提取了 {len(self.high_risk_connections)} 个高危连接")
        return self.high_risk_connections
    
    def _categorize_threat(self, beacon_score: float, long_conn: float, c2_dns: float, severity: str = "") -> str:
        """
        根据 RITA 阈值对威胁进行分类
        
        Returns:
            威胁级别: "high", "medium", "low", "base"
        """
        if severity in {"high", "medium", "low", "base"}:
            return severity

        # Beacon 评分判断（0-100）
        if beacon_score >= self.BEACON_THRESHOLDS["high"]:
            return "high"
        elif beacon_score >= self.BEACON_THRESHOLDS["medium"]:
            return "medium"
        
        # Long Connection 判断（秒）
        if long_conn >= self.LONG_CONN_THRESHOLDS["high"]:
            return "high"
        elif long_conn >= self.LONG_CONN_THRESHOLDS["medium"]:
            return "medium"
        
        # C2 Over DNS 判断（子域名数量）
        if c2_dns >= self.C2_DNS_THRESHOLDS["high"]:
            return "high"
        elif c2_dns >= self.C2_DNS_THRESHOLDS["medium"]:
            return "medium"
        
        return "low"

    @staticmethod
    def _normalize_key(key: str) -> str:
        """统一列名格式：大小写无关，空格/符号转下划线。"""
        normalized = key.strip().lower()
        for ch in [" ", "-", ":", "/", ".", "(", ")"]:
            normalized = normalized.replace(ch, "_")
        while "__" in normalized:
            normalized = normalized.replace("__", "_")
        return normalized.strip("_")

    def _normalize_row(self, row: dict[str, str]) -> dict[str, str]:
        """同时保留原始 key 和归一化 key，便于兼容多版本字段名。"""
        out: dict[str, str] = {}
        for k, v in row.items():
            if k is None:
                continue
            out[k] = v
            out[self._normalize_key(k)] = v
        return out

    @staticmethod
    def _pick(row: dict[str, str], *keys: str) -> str:
        """按候选列名顺序取第一个非空值。"""
        for key in keys:
            value = row.get(key)
            if value is not None and str(value).strip() != "":
                return str(value)
        return ""

    @staticmethod
    def _extract_port(port_proto_service: str) -> str:
        """解析 "80:tcp:http" 结构，提取端口。"""
        if not port_proto_service:
            return ""
        parts = str(port_proto_service).split(":")
        return parts[0].strip() if parts else ""
    
    @staticmethod
    def _safe_float(value: str) -> float:
        """安全转换为浮点数"""
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0
    
    @staticmethod
    def _safe_int(value: str) -> int:
        """安全转换为整数"""
        try:
            return int(float(value))
        except (ValueError, TypeError):
            return 0


class ZeekLogExtractor:
    """Zeek 日志提取器"""
    
    def __init__(self, log_dir: Path):
        """
        初始化提取器
        
        Args:
            log_dir: Zeek 日志目录路径
        """
        self.log_dir = Path(log_dir)
        self.conn_log: list[dict] = []
        self.ssl_log: list[dict] = []
        self.dns_log: list[dict] = []
        self.http_log: list[dict] = []
    
    def parse_all(self) -> None:
        """解析所有相关日志文件"""
        self._parse_tsv("conn.log", self.conn_log)
        self._parse_tsv("ssl.log", self.ssl_log)
        self._parse_tsv("dns.log", self.dns_log)
        self._parse_tsv("http.log", self.http_log)
        
        print(f"✓ Zeek 日志解析完成:")
        print(f"  - conn.log: {len(self.conn_log)} 条")
        print(f"  - ssl.log: {len(self.ssl_log)} 条")
        print(f"  - dns.log: {len(self.dns_log)} 条")
        print(f"  - http.log: {len(self.http_log)} 条")
    
    def _parse_tsv(self, filename: str, target_list: list[dict]) -> None:
        """
        解析 Zeek TSV 日志文件
        
        Args:
            filename: 日志文件名
            target_list: 存储解析结果的列表
        """
        log_path = self.log_dir / filename
        
        if not log_path.exists():
            return
        
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            
            # 提取字段名（#fields 行）
            fields = []
            data_lines = []
            
            for line in lines:
                if line.startswith("#fields"):
                    # 格式: #fields	ts	uid	id.orig_h	...
                    fields = line.strip().split("\t")[1:]
                elif not line.startswith("#"):
                    data_lines.append(line.strip())
            
            if not fields:
                return
            
            # 解析数据行
            for line in data_lines:
                if not line:
                    continue
                values = line.split("\t")
                if len(values) != len(fields):
                    continue
                
                row = dict(zip(fields, values))
                target_list.append(row)
                
        except Exception as e:
            print(f"⚠ 解析 {filename} 失败: {e}")
    
    def get_connection_details(self, src_ip: str, dst_ip: str) -> dict:
        """
        获取指定连接的详细信息
        
        Args:
            src_ip: 源 IP
            dst_ip: 目标 IP
        
        Returns:
            连接详情字典
        """
        details = {
            "conn_count": 0,
            "total_duration": 0.0,
            "total_bytes": 0,
            "avg_interval": 0.0,
            "tls_ja3": "",
            "tls_cipher": "",
            "tls_server_name": "",
            "dns_queries": [],
            "http_user_agents": [],
            "http_uris": [],
        }
        
        # 从 conn.log 提取连接统计
        matched_conns = [
            c for c in self.conn_log
            if c.get("id.orig_h") == src_ip and c.get("id.resp_h") == dst_ip
        ]
        
        details["conn_count"] = len(matched_conns)
        
        if matched_conns:
            durations = [self._safe_float(c.get("duration", "0")) for c in matched_conns]
            details["total_duration"] = sum(durations)
            
            bytes_list = [
                self._safe_int(c.get("orig_bytes", "0")) + self._safe_int(c.get("resp_bytes", "0"))
                for c in matched_conns
            ]
            details["total_bytes"] = sum(bytes_list)
            
            # 计算平均连接间隔
            timestamps = sorted([self._safe_float(c.get("ts", "0")) for c in matched_conns])
            if len(timestamps) > 1:
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                details["avg_interval"] = sum(intervals) / len(intervals)
        
        # 从 ssl.log 提取 TLS 信息
        matched_ssl = [
            s for s in self.ssl_log
            if s.get("id.orig_h") == src_ip and s.get("id.resp_h") == dst_ip
        ]
        
        if matched_ssl:
            ssl_entry = matched_ssl[0]  # 取第一条
            details["tls_ja3"] = ssl_entry.get("ja3", "")
            details["tls_cipher"] = ssl_entry.get("cipher", "")
            details["tls_server_name"] = ssl_entry.get("server_name", "")
        
        # 从 dns.log 提取 DNS 查询
        matched_dns = [
            d for d in self.dns_log
            if d.get("id.orig_h") == src_ip
        ]
        
        details["dns_queries"] = [
            d.get("query", "") for d in matched_dns[:10]  # 限制数量
        ]
        
        # 从 http.log 提取 HTTP 信息
        matched_http = [
            h for h in self.http_log
            if h.get("id.orig_h") == src_ip and h.get("id.resp_h") == dst_ip
        ]
        
        if matched_http:
            details["http_user_agents"] = list(set(
                h.get("user_agent", "") for h in matched_http[:10]
            ))
            details["http_uris"] = [
                h.get("uri", "") for h in matched_http[:10]
            ]
        
        return details
    
    @staticmethod
    def _safe_float(value: str) -> float:
        """安全转换为浮点数"""
        if value == "-":
            return 0.0
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0
    
    @staticmethod
    def _safe_int(value: str) -> int:
        """安全转换为整数"""
        if value == "-":
            return 0
        try:
            return int(float(value))
        except (ValueError, TypeError):
            return 0


class ThreatFeatureExtractor:
    """威胁特征提取器 - 从 RITA CSV 提取威胁特征"""
    
    def __init__(self, rita_csv: str):
        """
        初始化提取器
        
        Args:
            rita_csv: RITA CSV 文本
        """
        self.rita_extractor = RITADataExtractor(rita_csv)
    
    def extract_all(self) -> list[dict]:
        """
        提取所有威胁特征
        
        Returns:
            特征列表（纯 RITA 检测结果，不包含 Zeek 详情）
        """
        # 提取 RITA 高危连接
        high_risk = self.rita_extractor.extract_high_risk()
        
        if not high_risk:
            print("⚠ 没有检测到高危连接")
            return []
        
        print(f"✓ 提取了 {len(high_risk)} 个完整威胁特征")
        return high_risk


def main():
    """测试脚本"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python data_extractor.py <rita_csv_file>")
        sys.exit(1)
    
    rita_csv_path = Path(sys.argv[1])
    
    # 读取 RITA CSV
    with open(rita_csv_path, "r", encoding="utf-8") as f:
        rita_csv = f.read()
    
    # 提取特征
    extractor = ThreatFeatureExtractor(rita_csv)
    features = extractor.extract_all()
    
    # 显示前 3 个特征
    print("\n=== 威胁特征示例 ===")
    for i, feature in enumerate(features[:3], 1):
        print(f"\n特征 {i}:")
        print(f"  源 IP: {feature['src_ip']} → 目标 IP: {feature['dst_ip']}:{feature['dst_port']}")
        print(f"  Beacon 评分: {feature['beacon_score']:.1f}/100")
        print(f"  威胁级别: {feature['threat_category']}")
        if 'detection_sources' in feature:
            print(f"  检测来源: {', '.join(feature['detection_sources'])}")


if __name__ == "__main__":
    main()
