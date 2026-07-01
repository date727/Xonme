#!/usr/bin/env python3
"""
测试威胁特征合并器

模拟 RITA 和 LSTM 的检测结果，验证合并逻辑
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.threat_feature_merger import merge_threat_features


def main():
    # 模拟 RITA 检测结果（3 个威胁）
    rita_features = [
        {
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.5',
            'dst_port': '443',
            'beacon_score': 85.0,
            'long_conn_value': 0.0,
            'c2_over_dns_value': 0.0,
            'threat_category': 'medium',
            'connection_count': 50,
            'total_bytes': 102400,
        },
        {
            'src_ip': '192.168.1.101',
            'dst_ip': '10.0.0.6',
            'dst_port': '80',
            'beacon_score': 92.0,
            'long_conn_value': 0.0,
            'c2_over_dns_value': 0.0,
            'threat_category': 'high',
            'connection_count': 120,
            'total_bytes': 512000,
        },
        {
            'src_ip': '192.168.1.102',
            'dst_ip': '10.0.0.7',
            'dst_port': '8080',
            'beacon_score': 72.0,
            'long_conn_value': 0.0,
            'c2_over_dns_value': 0.0,
            'threat_category': 'low',
            'connection_count': 25,
            'total_bytes': 51200,
        },
    ]
    
    # 模拟 LSTM 检测结果（4 个威胁，与 RITA 有 2 个重叠）
    lstm_results = {
        'beacons': [
            # 与 RITA 第1个重叠
            {
                'src': '192.168.1.100',
                'dst': '10.0.0.5',
                'port': '443',
                'proto': 'tcp',
                'confidence': 95.3,
                'risk': 'Critical',
            },
            # 与 RITA 第2个重叠
            {
                'src': '192.168.1.101',
                'dst': '10.0.0.6',
                'port': '80',
                'proto': 'tcp',
                'confidence': 88.7,
                'risk': 'High',
            },
            # LSTM 独立检测（RITA 未发现）
            {
                'src': '192.168.1.200',
                'dst': '10.0.0.99',
                'port': '8443',
                'proto': 'tcp',
                'confidence': 76.5,
                'risk': 'High',
            },
            {
                'src': '192.168.1.201',
                'dst': '10.0.0.100',
                'port': '443',
                'proto': 'tcp',
                'confidence': 65.2,
                'risk': 'Medium',
            },
        ],
        'total_connections': 1000,
        'total_flagged': 4,
        'summary_text': 'The LSTM beacon detection model analyzed 1000 connections and flagged **4** as potential C2 beacons.',
    }
    
    # 模拟 Zeek 日志目录（不再使用）
    # zeek_log_dir = Path("outputs/test")
    
    print("=" * 80)
    print("威胁特征合并器测试")
    print("=" * 80)
    print(f"\n输入:")
    print(f"  RITA 检测: {len(rita_features)} 个威胁")
    print(f"  LSTM 检测: {len(lstm_results['beacons'])} 个威胁")
    print()
    
    # 执行合并（不再需要 zeek_log_dir）
    merged = merge_threat_features(rita_features, lstm_results)
    
    print("\n" + "=" * 80)
    print("合并结果")
    print("=" * 80)
    print(f"总威胁数: {len(merged)}\n")
    
    # 显示合并后的威胁
    for i, threat in enumerate(merged, 1):
        print(f"威胁 {i}:")
        print(f"  连接: {threat['src_ip']:15} → {threat['dst_ip']:15} :{threat['dst_port']}")
        print(f"  检测来源: {', '.join(threat['detection_sources'])}")
        
        if 'RITA' in threat['detection_sources']:
            print(f"  RITA Beacon Score: {threat['beacon_score']:.1f}")
        
        if 'LSTM' in threat['detection_sources']:
            print(f"  LSTM Confidence: {threat['lstm_confidence']:.1f}% ({threat['lstm_risk']})")
        
        print(f"  威胁等级: {threat['threat_category']}")
        print()
    
    # 统计
    print("=" * 80)
    print("统计信息")
    print("=" * 80)
    
    rita_only = [t for t in merged if t['detection_sources'] == ['RITA']]
    lstm_only = [t for t in merged if t['detection_sources'] == ['LSTM']]
    both = [t for t in merged if len(t['detection_sources']) == 2]
    
    print(f"RITA 独立检测: {len(rita_only)} 个")
    print(f"LSTM 独立检测: {len(lstm_only)} 个")
    print(f"两者都检测到: {len(both)} 个")
    print()
    
    print("预期结果:")
    print("  - RITA 独立: 1 个 (192.168.1.102)")
    print("  - LSTM 独立: 2 个 (192.168.1.200, 192.168.1.201)")
    print("  - 两者都检测: 2 个 (192.168.1.100, 192.168.1.101)")
    print("  - 总计: 5 个唯一威胁")
    print()
    
    # 验证
    if len(merged) == 5:
        print("✓ 测试通过：合并逻辑正确！")
    else:
        print(f"✗ 测试失败：期望 5 个威胁，实际 {len(merged)} 个")
    
    print("=" * 80)


if __name__ == "__main__":
    main()
