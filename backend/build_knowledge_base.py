#!/usr/bin/env python3
"""
知识库构建脚本
从 MITRE ATT&CK STIX 数据构建向量知识库

支持两种模式:
  - 单文件模式: --stix-file <path>  解析单个 STIX JSON
  - 目录模式 (默认): 自动扫描 attack-stix-data 目录，解析 Enterprise + ICS + Mobile
"""

import argparse
import sys
from pathlib import Path

# 添加 app 目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent))

from app.knowledge_base.stix_parser import STIXParser
from app.knowledge_base.vector_db import VectorKnowledgeBase, VECTOR_DB_AVAILABLE

# 默认要扫描的领域文件（相对于 stix-dir 目录内部的路径，无版本号 = 最新版）
DEFAULT_DOMAINS = [
    "enterprise-attack/enterprise-attack.json",
    "ics-attack/ics-attack.json",
    "mobile-attack/mobile-attack.json",
]

LOCAL_EMBEDDING_MODEL_PATH = Path(__file__).resolve().parent / "local_models" / "all-MiniLM-L6-v2"
DEFAULT_CHROMA_DB_PATH = Path(__file__).resolve().parent / "chroma_db"


def discover_stix_files(base_dir: str | Path) -> list[Path]:
    """自动发现目录下的最新版 STIX 文件（enterprise + ics + mobile）"""
    base_dir = Path(base_dir).resolve()
    stix_files: list[Path] = []

    for rel_path in DEFAULT_DOMAINS:
        candidate = base_dir / rel_path
        if candidate.exists():
            stix_files.append(candidate)

    return stix_files


def main():
    parser = argparse.ArgumentParser(
        description="构建 MITRE ATT&CK APT 组织向量知识库"
    )
    parser.add_argument(
        "--stix-file",
        type=str,
        default=None,
        help="单个 STIX JSON 文件路径（指定后仅解析该文件）",
    )
    parser.add_argument(
        "--stix-dir",
        type=str,
        default="../attack-stix-data",
        help="STIX 数据目录（默认自动扫描 Enterprise + ICS + Mobile 最新版）",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=str(DEFAULT_CHROMA_DB_PATH),
        help="ChromaDB 数据库路径（默认: backend/chroma_db）",
    )
    parser.add_argument(
        "--embedding-model",
        type=str,
        default=str(LOCAL_EMBEDDING_MODEL_PATH),
        help="Embedding 模型路径（默认使用项目内本地模型）",
    )
    parser.add_argument(
        "--export-json",
        type=str,
        help="导出知识库为 JSON 文件（可选）",
    )
    parser.add_argument(
        "--test-query",
        action="store_true",
        help="构建后运行测试查询",
    )

    args = parser.parse_args()

    # 检查依赖
    if not VECTOR_DB_AVAILABLE:
        print("❌ 缺少依赖，请先安装:")
        print("   pip install chromadb sentence-transformers")
        sys.exit(1)

    # 确定要解析的 STIX 文件列表
    if args.stix_file:
        # 单文件模式
        stix_path = Path(args.stix_file)
        if not stix_path.exists():
            print(f"❌ STIX 文件不存在: {stix_path}")
            sys.exit(1)
        stix_files = [stix_path]
    else:
        # 目录扫描模式（默认）
        stix_files = discover_stix_files(args.stix_dir)
        if not stix_files:
            print(f"❌ 在目录 {args.stix_dir} 中未找到任何 STIX 文件")
            print(f"   请确保 attack-stix-data 目录存在，或使用 --stix-file 手动指定")
            sys.exit(1)

    print("=" * 60)
    print("MITRE ATT&CK 向量知识库构建工具")
    print("=" * 60)

    # 步骤 1: 解析 STIX 数据
    print(f"\n[1/3] 解析 STIX 数据 ({len(stix_files)} 个文件)...")
    for f in stix_files:
        print(f"      - {f.name}")

    stix_parser = STIXParser(stix_paths=stix_files)
    documents = stix_parser.build_rag_documents()

    if not documents:
        print("❌ 没有生成任何文档，请检查 STIX 文件")
        sys.exit(1)

    # 步骤 2: 构建向量索引
    print(f"\n[2/3] 构建向量索引...")
    print(f"      数据库路径: {args.db_path}")
    print(f"      Embedding 模型: {args.embedding_model}")

    kb = VectorKnowledgeBase(
        db_path=args.db_path,
        collection_name="apt_groups",
        embedding_model=args.embedding_model,
    )
    kb.build_index(documents)

    # 步骤 3: 验证和导出
    print(f"\n[3/3] 验证知识库...")
    stats = kb.get_stats()
    print(f"✓ 知识库构建成功!")
    print(f"  - 文档数量: {stats['document_count']}")
    print(f"  - 存储位置: {stats['db_path']}")

    # 导出 JSON
    if args.export_json:
        print(f"\n导出知识库到 JSON...")
        kb.export_to_json(args.export_json)

    # 测试查询
    if args.test_query:
        print("\n" + "=" * 60)
        print("测试查询")
        print("=" * 60)

        test_queries = [
            "使用 DNS 隧道进行 C2 通信的 APT 组织",
            "TLS 加密的 Beacon 通信",
            "通过非标准端口建立长连接",
            "使用代理或协议隧道隐藏流量",
        ]

        for query in test_queries:
            print(f"\n查询: {query}")
            results = kb.search(query, top_k=3)

            if not results:
                print("  未找到匹配结果")
                continue

            for i, result in enumerate(results, 1):
                print(f"  {i}. {result['name']}")
                print(f"     相似度: {result['score']:.3f}")
                print(f"     C2 技术: {', '.join(result['metadata']['c2_techniques'][:5])}")
                print(f"     URL: {result['metadata']['mitre_url']}")

    print("\n" + "=" * 60)
    print("✓ 完成！知识库已就绪，可用于威胁归因分析")
    print("=" * 60)


if __name__ == "__main__":
    main()
