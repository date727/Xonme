"""
Zeek 原始日志 → LSTM 特征转换器

直接从 Zeek conn.log 提取所有连接的 IAT 特征，不依赖 RITA 筛选。
这样可以让 LSTM 分析全部流量，弥补 RITA 可能的漏检。
"""

import csv
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple
import numpy as np


class ZeekToLSTMConverter:
    """从 Zeek conn.log 构建 LSTM 特征 CSV"""
    
    def __init__(self, zeek_log_dir: Path):
        """
        初始化转换器
        
        Args:
            zeek_log_dir: Zeek 日志目录路径
        """
        self.zeek_log_dir = Path(zeek_log_dir)
        self.connections: List[Dict] = []
        
    def parse_conn_log(self) -> None:
        """解析 conn.log 文件"""
        conn_log_path = self.zeek_log_dir / "conn.log"
        
        if not conn_log_path.exists():
            print(f"⚠ conn.log 未找到: {conn_log_path}")
            return
        
        try:
            with open(conn_log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            
            # 提取字段名
            fields = []
            data_lines = []
            
            for line in lines:
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]
                elif not line.startswith("#"):
                    data_lines.append(line.strip())
            
            if not fields:
                print("⚠ conn.log 没有 #fields 行")
                return
            
            # 解析数据行
            for line in data_lines:
                if not line:
                    continue
                values = line.split("\t")
                if len(values) != len(fields):
                    continue
                
                row = dict(zip(fields, values))
                self.connections.append(row)
            
            print(f"✓ 从 conn.log 解析了 {len(self.connections)} 条连接")
            
        except Exception as e:
            print(f"❌ 解析 conn.log 失败: {e}")
    
    def build_iat_features(self) -> str:
        """
        按 (src, dst, port, proto) 分组，计算 IAT 特征
        
        Returns:
            CSV 文本，包含 15 维 iat_oresp_* 特征
        """
        if not self.connections:
            self.parse_conn_log()
        
        if not self.connections:
            return ""
        
        # 按连接四元组分组
        grouped: Dict[Tuple, List[Dict]] = defaultdict(list)
        
        for conn in self.connections:
            src = conn.get("id.orig_h", "")
            dst = conn.get("id.resp_h", "")
            port = conn.get("id.resp_p", "")
            proto = conn.get("proto", "")
            
            if not src or not dst:
                continue
            
            key = (src, dst, port, proto)
            grouped[key].append(conn)
        
        print(f"✓ 分组后共 {len(grouped)} 个唯一连接")
        
        # 为每个连接组计算 IAT 特征
        feature_rows = []
        
        for (src, dst, port, proto), conn_list in grouped.items():
            # 按时间戳排序
            sorted_conns = sorted(
                conn_list,
                key=lambda c: self._safe_float(c.get("ts", "0"))
            )
            
            if len(sorted_conns) < 2:
                # 单个连接没有 IAT，跳过或使用零值
                continue
            
            # 计算时间间隔（秒）
            timestamps = [self._safe_float(c.get("ts", "0")) for c in sorted_conns]
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            if not intervals:
                continue
            
            # 计算包数量
            packet_nb = sum(
                self._safe_int(c.get("orig_pkts", "0")) + self._safe_int(c.get("resp_pkts", "0"))
                for c in sorted_conns
            )
            
            # 构建 IAT 直方图（频率统计）
            iat_features = self._compute_iat_features(intervals)
            
            # 构建 CSV 行
            feature_rows.append({
                "src": src,
                "dst": dst,
                "port": port,
                "proto": proto,
                "packet_nb": packet_nb,
                **iat_features
            })
        
        print(f"✓ 生成了 {len(feature_rows)} 条 LSTM 特征记录")
        
        # 转换为 CSV 文本
        if not feature_rows:
            return ""
        
        fieldnames = [
            "src", "dst", "port", "proto", "packet_nb",
            "iat_oresp_total", "iat_oresp_min", "iat_oresp_max",
            "iat_oresp_mean", "iat_oresp_stddev",
            "iat_oresp_nf_0", "iat_oresp_nf_1", "iat_oresp_nf_2",
            "iat_oresp_nf_3", "iat_oresp_nf_4", "iat_oresp_nf_5",
            "iat_oresp_nf_6", "iat_oresp_nf_7", "iat_oresp_nf_8",
            "iat_oresp_nf_9",
        ]
        
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(feature_rows)
        
        return output.getvalue()
    
    def _compute_iat_features(self, intervals: List[float]) -> Dict[str, float]:
        """
        计算 IAT 的 15 维统计特征
        
        Args:
            intervals: 时间间隔列表（秒）
        
        Returns:
            特征字典
        """
        intervals_array = np.array(intervals)
        
        # 基本统计量
        total = float(np.sum(intervals_array))
        min_val = float(np.min(intervals_array))
        max_val = float(np.max(intervals_array))
        mean_val = float(np.mean(intervals_array))
        stddev_val = float(np.std(intervals_array))
        
        # 频率直方图（归一化）
        # 方法：将间隔值分桶，统计每个桶的频率
        hist, _ = np.histogram(intervals_array, bins=10)
        freq_normalized = hist / len(intervals_array)
        
        # 取前 10 个归一化频率
        nf_values = freq_normalized.tolist()[:10]
        # 不足 10 个补 0
        nf_values += [0.0] * (10 - len(nf_values))
        
        features = {
            "iat_oresp_total": total,
            "iat_oresp_min": min_val,
            "iat_oresp_max": max_val,
            "iat_oresp_mean": mean_val,
            "iat_oresp_stddev": stddev_val,
        }
        
        for i in range(10):
            features[f"iat_oresp_nf_{i}"] = nf_values[i]
        
        return features
    
    @staticmethod
    def _safe_float(value: str) -> float:
        """安全转换为浮点数"""
        if value == "-" or not value:
            return 0.0
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0
    
    @staticmethod
    def _safe_int(value: str) -> int:
        """安全转换为整数"""
        if value == "-" or not value:
            return 0
        try:
            return int(float(value))
        except (ValueError, TypeError):
            return 0


def export_lstm_features_from_zeek(zeek_log_dir: Path) -> str:
    """
    从 Zeek 日志目录导出 LSTM 特征 CSV
    
    Args:
        zeek_log_dir: Zeek 日志目录路径
    
    Returns:
        CSV 文本
    """
    converter = ZeekToLSTMConverter(zeek_log_dir)
    return converter.build_iat_features()


def main():
    """测试脚本"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python zeek_to_lstm_converter.py <zeek_log_dir>")
        sys.exit(1)
    
    zeek_log_dir = Path(sys.argv[1])
    
    print(f"正在处理: {zeek_log_dir}")
    csv_text = export_lstm_features_from_zeek(zeek_log_dir)
    
    if csv_text:
        # 保存到文件
        output_path = zeek_log_dir / "lstm_features.csv"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(csv_text)
        print(f"✓ 特征已保存至: {output_path}")
        
        # 显示前几行
        print("\n=== 特征预览 ===")
        print("\n".join(csv_text.splitlines()[:5]))
    else:
        print("❌ 未生成任何特征")


if __name__ == "__main__":
    main()
