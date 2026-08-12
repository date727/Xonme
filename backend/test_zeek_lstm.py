#!/usr/bin/env python3
"""
测试 Zeek → LSTM 转换器

用法:
    python test_zeek_lstm.py <zeek_log_dir>
"""

import sys
from pathlib import Path

# 确保能导入 app 模块
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.zeek_to_lstm_converter import export_lstm_features_from_zeek
from app.lstm_predictor import predict_beacons


def main():
    if len(sys.argv) < 2:
        print("用法: python test_zeek_lstm.py <zeek_log_dir>")
        print("示例: python test_zeek_lstm.py outputs/abc123")
        sys.exit(1)
    
    zeek_log_dir = Path(sys.argv[1])
    
    if not zeek_log_dir.exists():
        print(f"❌ 目录不存在: {zeek_log_dir}")
        sys.exit(1)
    
    print("=" * 80)
    print("Zeek → LSTM 转换器测试")
    print("=" * 80)
    print(f"输入目录: {zeek_log_dir}")
    print()
    
    # 步骤 1: 从 Zeek 日志提取特征
    print("步骤 1: 提取 LSTM 特征...")
    print("-" * 80)
    lstm_csv = export_lstm_features_from_zeek(zeek_log_dir)
    
    if not lstm_csv:
        print("❌ 未提取到任何特征")
        sys.exit(1)
    
    print()
    print("✓ 特征提取成功！")
    print()
    
    # 显示 CSV 前几行
    lines = lstm_csv.splitlines()
    print("CSV 预览（前 10 行）:")
    print("-" * 80)
    for line in lines[:10]:
        print(line)
    print("-" * 80)
    print(f"总行数: {len(lines)}")
    print()
    
    # 步骤 2: LSTM 预测
    print("步骤 2: LSTM Beacon 检测...")
    print("-" * 80)
    
    try:
        results = predict_beacons(lstm_csv, threshold=0.5)
        
        if results is None:
            print("⚠ LSTM 预测失败（可能是模型未加载或特征不匹配）")
            sys.exit(1)
        
        print()
        print("=" * 80)
        print("检测结果")
        print("=" * 80)
        print(f"总连接数: {results['total_connections']}")
        print(f"标记为 Beacon: {results['total_flagged']}")
        print()
        
        if results['total_flagged'] > 0:
            print("检测到的 Beacon:")
            print("-" * 80)
            beacons = results['beacons']
            for i, b in enumerate(beacons[:20], 1):  # 最多显示 20 个
                print(f"{i}. {b['src']:15} → {b['dst']:15} "
                      f":{b['port']:5} {b['proto']:3} "
                      f"| 置信度: {b['confidence']:5.1f}% "
                      f"| 风险: {b['risk']}")
            
            if len(beacons) > 20:
                print(f"... 还有 {len(beacons) - 20} 个未显示")
        else:
            print("✓ 未检测到 Beacon 行为")
        
        print("=" * 80)
        
    except Exception as e:
        print(f"❌ LSTM 预测失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
