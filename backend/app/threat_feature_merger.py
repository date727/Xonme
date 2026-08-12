"""
威胁特征合并器

整合 RITA 和 LSTM 的检测结果，为 RAG 提供完整的威胁视图。

架构说明：
    RITA 检测结果 ──┐
                    ├──→ 合并器 ──→ RAG 输入
    LSTM 检测结果 ──┘

合并器只使用 RITA 和 LSTM 的输出，不再二次解析 Zeek 原始日志。
这样可以避免重复解析，提高性能，简化架构。
"""

from pathlib import Path
from typing import Dict, List, Set, Tuple


class ThreatFeatureMerger:
    """合并 RITA 和 LSTM 的威胁检测结果"""
    
    def __init__(
        self,
        rita_features: List[Dict],
        lstm_results: Dict | None,
        rita_evidence: Dict[Tuple, Dict] | None = None,
    ):
        """
        初始化合并器
        
        Args:
            rita_features: RITA 提取的高危连接列表
            lstm_results: LSTM 检测结果字典
        """
        self.rita_features = rita_features
        self.lstm_results = lstm_results
        self.rita_evidence = rita_evidence or {}
        
    def merge(self) -> List[Dict]:
        """
        合并 RITA 和 LSTM 的结果
        
        返回:
            合并后的威胁特征列表
        """
        merged_features = []
        
        # 1. 从 RITA 获取的威胁
        rita_connections = self._get_rita_connections()
        
        # 2. 从 LSTM 获取的威胁
        lstm_connections = self._get_lstm_connections()
        
        # 3. 构建连接索引（src, dst, port）
        all_connection_keys: Set[Tuple] = set()
        
        # 添加 RITA 检测的连接
        for feature in self.rita_features:
            key = (
                feature.get('src_ip', ''),
                feature.get('dst_ip', ''),
                str(feature.get('dst_port', '')),
            )
            all_connection_keys.add(key)
        
        # 添加 LSTM 检测的连接
        for conn_key in lstm_connections.keys():
            all_connection_keys.add(conn_key)
        
        print(f"✓ 合并器: RITA 检测 {len(rita_connections)} 个威胁, "
              f"LSTM 检测 {len(lstm_connections)} 个威胁, "
              f"合并后共 {len(all_connection_keys)} 个唯一威胁")
        
        # 4. 为每个唯一连接构建完整特征
        for conn_key in all_connection_keys:
            src, dst, port = conn_key
            
            # 基础特征
            feature = {
                'src_ip': src,
                'dst_ip': dst,
                'dst_port': port,
                'detection_sources': [],  # 记录检测来源
            }
            
            # 合并 RITA 特征
            if conn_key in rita_connections:
                rita_feature = rita_connections[conn_key]
                feature.update({
                    'beacon_score': rita_feature.get('beacon_score', 0.0),
                    'long_conn_value': rita_feature.get('long_conn_value', 0.0),
                    'c2_over_dns_value': rita_feature.get('c2_over_dns_value', 0.0),
                    'threat_category': rita_feature.get('threat_category', 'unknown'),
                    'connection_count': rita_feature.get('connection_count', 0),
                    'total_bytes': rita_feature.get('total_bytes', 0),
                    'rita': self.rita_evidence.get(conn_key, {}),
                })
                feature['detection_sources'].append('RITA')
            else:
                # LSTM 独立检测，RITA 未标记
                feature.update({
                    'beacon_score': 0.0,
                    'long_conn_value': 0.0,
                    'c2_over_dns_value': 0.0,
                    'threat_category': 'lstm_only',
                    'connection_count': 0,
                    'total_bytes': 0,
                    'rita': {},
                })
            
            # 合并 LSTM 特征
            if conn_key in lstm_connections:
                lstm_feature = lstm_connections[conn_key]
                feature.update({
                    'lstm_confidence': lstm_feature.get('confidence', 0.0),
                    'lstm_risk': lstm_feature.get('risk', 'Unknown'),
                })
                feature['detection_sources'].append('LSTM')
                
                # 如果 RITA 没标记但 LSTM 标记了，提升威胁等级
                if 'RITA' not in feature['detection_sources']:
                    # 根据 LSTM 置信度推断威胁等级
                    if lstm_feature.get('confidence', 0) >= 90:
                        feature['threat_category'] = 'high'
                    elif lstm_feature.get('confidence', 0) >= 75:
                        feature['threat_category'] = 'medium'
                    else:
                        feature['threat_category'] = 'low'
            else:
                feature.update({
                    'lstm_confidence': 0.0,
                    'lstm_risk': 'Not Detected',
                })
            
            # 注意：不再从 Zeek 日志补充详细信息
            # 所有需要的特征应该已经包含在 RITA 和 LSTM 的输出中
            
            merged_features.append(feature)
        
        # 5. 按威胁等级和置信度排序
        merged_features.sort(
            key=lambda f: (
                self._threat_priority(f.get('threat_category', '')),
                -f.get('lstm_confidence', 0.0),
                -f.get('beacon_score', 0.0)
            )
        )
        
        print(f"✓ 合并器: 生成 {len(merged_features)} 个完整威胁特征")
        
        return merged_features
    
    def _get_rita_connections(self) -> Dict[Tuple, Dict]:
        """构建 RITA 连接索引"""
        connections = {}
        for feature in self.rita_features:
            key = (
                feature.get('src_ip', ''),
                feature.get('dst_ip', ''),
                str(feature.get('dst_port', '')),
            )
            connections[key] = feature
        return connections
    
    def _get_lstm_connections(self) -> Dict[Tuple, Dict]:
        """构建 LSTM 连接索引"""
        connections = {}
        
        if not self.lstm_results or not self.lstm_results.get('beacons'):
            return connections
        
        for beacon in self.lstm_results['beacons']:
            key = (
                beacon.get('src', ''),
                beacon.get('dst', ''),
                str(beacon.get('port', '')),
            )
            connections[key] = beacon
        
        return connections
    
    @staticmethod
    def _threat_priority(category: str) -> int:
        """威胁等级优先级（数字越小优先级越高）"""
        priority_map = {
            'high': 0,
            'critical': 0,
            'medium': 1,
            'low': 2,
            'lstm_only': 1,  # LSTM 独立检测视为中等优先级
            'base': 3,
            'unknown': 4,
        }
        return priority_map.get(category.lower(), 5)


def merge_threat_features(
    rita_features: List[Dict],
    lstm_results: Dict | None,
    rita_evidence: Dict[Tuple, Dict] | None = None,
) -> List[Dict]:
    """
    合并 RITA 和 LSTM 的威胁检测结果
    
    Args:
        rita_features: RITA 提取的威胁特征
        lstm_results: LSTM 检测结果
    
    Returns:
        合并后的威胁特征列表
    """
    merger = ThreatFeatureMerger(rita_features, lstm_results, rita_evidence)
    return merger.merge()


def main():
    """测试脚本"""
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python threat_feature_merger.py <lstm_results.json>")
        sys.exit(1)
    
    lstm_results_path = Path(sys.argv[1])
    
    # 模拟 RITA 特征
    rita_features = [
        {
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.5',
            'dst_port': '443',
            'beacon_score': 85.0,
            'threat_category': 'medium',
        }
    ]
    
    # 加载 LSTM 结果
    with open(lstm_results_path, 'r') as f:
        lstm_results = json.load(f)
    
    # 合并
    merged = merge_threat_features(rita_features, lstm_results)
    
    # 显示结果
    print("\n=== 合并后的威胁特征 ===")
    for i, feature in enumerate(merged[:10], 1):
        print(f"\n威胁 {i}:")
        print(f"  连接: {feature['src_ip']} → {feature['dst_ip']}:{feature['dst_port']}")
        print(f"  检测来源: {', '.join(feature['detection_sources'])}")
        print(f"  RITA Beacon Score: {feature['beacon_score']:.1f}")
        print(f"  LSTM Confidence: {feature['lstm_confidence']:.1f}%")
        print(f"  威胁等级: {feature['threat_category']}")


if __name__ == "__main__":
    main()
