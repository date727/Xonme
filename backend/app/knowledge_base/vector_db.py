"""
向量知识库模块
使用 ChromaDB 构建轻量级向量数据库，支持 APT 组织的语义检索
"""

import json
from pathlib import Path
from typing import Any


LOCAL_EMBEDDING_MODEL_PATH = (
    Path(__file__).resolve().parents[2] / "local_models" / "all-MiniLM-L6-v2"
)
DEFAULT_CHROMA_DB_PATH = Path(__file__).resolve().parents[2] / "chroma_db"

try:
    import chromadb
    from chromadb.config import Settings
    from sentence_transformers import SentenceTransformer
    VECTOR_DB_AVAILABLE = True
except ImportError:
    VECTOR_DB_AVAILABLE = False
    chromadb = None
    SentenceTransformer = None


class VectorKnowledgeBase:
    """向量知识库 - 基于 ChromaDB 的轻量实现"""
    
    def __init__(
        self,
        db_path: str | Path = DEFAULT_CHROMA_DB_PATH,
        collection_name: str = "apt_groups",
        embedding_model: str | Path = LOCAL_EMBEDDING_MODEL_PATH,
    ):
        """
        初始化向量知识库
        
        Args:
            db_path: ChromaDB 数据库路径
            collection_name: 集合名称
            embedding_model: Embedding 模型名称
                - 英文轻量: sentence-transformers/all-MiniLM-L6-v2 (80MB)
                - 英文高质量: sentence-transformers/all-mpnet-base-v2 (420MB)
                - 中文: BAAI/bge-small-zh-v1.5 (100MB)
        """
        if not VECTOR_DB_AVAILABLE:
            raise ImportError(
                "向量数据库依赖未安装。请运行:\n"
                "pip install chromadb sentence-transformers"
            )
        
        self.db_path = Path(db_path)
        self.collection_name = collection_name
        self.embedding_model_name = str(embedding_model)
        
        # 初始化 ChromaDB 客户端（持久化存储）
        self.client = chromadb.PersistentClient(
            path=str(self.db_path),
            settings=Settings(anonymized_telemetry=False)
        )
        
        # 加载 Embedding 模型
        model_path = str(embedding_model)
        print(f"正在加载 Embedding 模型: {model_path}")
        self.embedding_model = SentenceTransformer(model_path)
        print("✓ Embedding 模型加载完成")
        
        # 获取或创建集合
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"description": "MITRE ATT&CK APT 组织知识库"}
        )
        
    def build_index(self, documents: list[dict], batch_size: int = 32) -> None:
        """
        构建向量索引
        
        Args:
            documents: 文档列表，每个文档包含:
                - id: 唯一标识符
                - text: 文本内容
                - metadata: 元数据字典
            batch_size: 批处理大小
        """
        if not documents:
            print("⚠ 没有文档需要索引")
            return
        
        # 清空现有集合（重建索引）
        self.client.delete_collection(self.collection_name)
        self.collection = self.client.create_collection(
            name=self.collection_name,
            metadata={"description": "MITRE ATT&CK APT 组织知识库"}
        )
        
        print(f"开始构建索引，共 {len(documents)} 个文档...")
        
        # 批量处理
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]
            
            ids = [doc["id"] for doc in batch]
            texts = [doc["text"] for doc in batch]
            metadatas = [doc["metadata"] for doc in batch]
            
            # 生成 Embeddings
            embeddings = self.embedding_model.encode(
                texts,
                show_progress_bar=True,
                batch_size=batch_size,
            ).tolist()
            
            # 添加到集合
            self.collection.add(
                ids=ids,
                documents=texts,
                embeddings=embeddings,
                metadatas=metadatas,
            )
            
            print(f"  已处理 {min(i + batch_size, len(documents))}/{len(documents)} 个文档")
        
        print(f"✓ 索引构建完成，当前集合包含 {self.collection.count()} 个文档")
    
    def search(
        self,
        query: str,
        top_k: int = 5,
        filter_metadata: dict[str, Any] | None = None,
        group_by_apt: bool = True,
    ) -> list[dict]:
        """
        语义检索
        
        Args:
            query: 查询文本
            top_k: 返回结果数量
            filter_metadata: 元数据过滤条件（可选）
        
        Returns:
            检索结果列表，每个结果包含:
                - id: 文档 ID
                - name: APT 组织名称
                - distance: 相似度距离（越小越相似）
                - score: 相似度分数（0-1，越大越相似）
                - metadata: 元数据
                - text: 文档内容（可选）
        """
        if self.collection.count() == 0:
            print("⚠ 知识库为空，请先构建索引")
            return []
        
        # 生成查询向量
        query_embedding = self.embedding_model.encode(query).tolist()
        
        # 执行检索。证据级知识库需要多取一些 chunk，再聚合成组织候选。
        n_results = top_k
        if group_by_apt:
            n_results = min(max(top_k * 8, top_k), self.collection.count())

        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            where=filter_metadata,
            include=["metadatas", "documents", "distances"],
        )
        
        # 格式化结果
        chunk_results = []
        for i in range(len(results["ids"][0])):
            distance = results["distances"][0][i]
            # 转换为相似度分数（ChromaDB 使用 L2 距离）
            score = 1 / (1 + distance)
            
            chunk_results.append({
                "id": results["ids"][0][i],
                "name": results["metadatas"][0][i].get("name", "Unknown"),
                "distance": distance,
                "score": score,
                "metadata": results["metadatas"][0][i],
                "text": results["documents"][0][i],
            })
        
        if not group_by_apt:
            return chunk_results[:top_k]

        return self._aggregate_evidence_chunks(chunk_results, top_k=top_k)

    @staticmethod
    def _aggregate_evidence_chunks(chunk_results: list[dict], top_k: int) -> list[dict]:
        """Aggregate evidence-level retrieval hits into APT group candidates."""
        grouped: dict[str, dict] = {}

        for chunk in chunk_results:
            metadata = chunk["metadata"]
            group_key = metadata.get("group_id") or metadata.get("name") or chunk["id"]
            technique_id = metadata.get("technique_id")

            if group_key not in grouped:
                grouped[group_key] = {
                    "id": group_key,
                    "name": chunk["name"],
                    "distance": chunk["distance"],
                    "score": chunk["score"],
                    "metadata": {
                        "name": chunk["name"],
                        "aliases": metadata.get("aliases", []),
                        "mitre_url": metadata.get("mitre_url", ""),
                        "technique_count": metadata.get("technique_count", 0),
                        "c2_technique_count": metadata.get("c2_technique_count", 0),
                        "c2_techniques": [],
                        "matched_techniques": [],
                    },
                    "text": chunk["text"],
                    "evidence_chunks": [],
                }

            group = grouped[group_key]
            group["distance"] = min(group["distance"], chunk["distance"])
            group["score"] = max(group["score"], chunk["score"])
            group["evidence_chunks"].append({
                "id": chunk["id"],
                "score": chunk["score"],
                "distance": chunk["distance"],
                "technique_id": technique_id,
                "technique_name": metadata.get("technique_name", ""),
                "text": chunk["text"],
            })

            for tech in metadata.get("c2_techniques", []) or []:
                if tech not in group["metadata"]["c2_techniques"]:
                    group["metadata"]["c2_techniques"].append(tech)
            if technique_id and technique_id not in group["metadata"]["matched_techniques"]:
                group["metadata"]["matched_techniques"].append(technique_id)

        aggregated = []
        for group in grouped.values():
            evidence = sorted(
                group["evidence_chunks"],
                key=lambda item: item["score"],
                reverse=True,
            )
            group["evidence_chunks"] = evidence[:5]

            top_scores = [item["score"] for item in evidence[:3]]
            if top_scores:
                # Preserve the strongest evidence, with a small bonus for repeated
                # independently retrieved technique evidence for the same group.
                group["score"] = min(
                    1.0,
                    top_scores[0] + 0.03 * (len(top_scores) - 1),
                )

            group["metadata"]["matched_techniques"] = [
                item["technique_id"]
                for item in evidence
                if item.get("technique_id")
            ][:5]
            group["text"] = evidence[0]["text"] if evidence else group["text"]
            aggregated.append(group)

        aggregated.sort(key=lambda item: item["score"], reverse=True)
        return aggregated[:top_k]
    
    def get_stats(self) -> dict:
        """获取知识库统计信息"""
        return {
            "collection_name": self.collection_name,
            "document_count": self.collection.count(),
            "embedding_model": self.embedding_model_name,
            "db_path": str(self.db_path),
        }
    
    def export_to_json(self, output_path: str | Path) -> None:
        """导出知识库为 JSON（用于备份或分析）"""
        output_path = Path(output_path)
        
        # 获取所有文档
        all_docs = self.collection.get(
            include=["metadatas", "documents"]
        )
        
        export_data = {
            "collection_name": self.collection_name,
            "document_count": len(all_docs["ids"]),
            "documents": [
                {
                    "id": all_docs["ids"][i],
                    "text": all_docs["documents"][i],
                    "metadata": all_docs["metadatas"][i],
                }
                for i in range(len(all_docs["ids"]))
            ]
        }
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)
        
        print(f"✓ 知识库已导出到: {output_path}")


def main():
    """测试脚本 - 构建知识库"""
    import sys
    from .stix_parser import STIXParser
    
    if len(sys.argv) < 2:
        print("Usage: python vector_db.py <path_to_stix_json>")
        sys.exit(1)
    
    # 解析 STIX 数据
    print("=== 步骤 1: 解析 STIX 数据 ===")
    parser = STIXParser(sys.argv[1])
    documents = parser.build_rag_documents()
    
    # 构建向量知识库
    print("\n=== 步骤 2: 构建向量知识库 ===")
    kb = VectorKnowledgeBase(
        db_path="./chroma_db",
        embedding_model=LOCAL_EMBEDDING_MODEL_PATH,
    )
    kb.build_index(documents)
    
    # 测试检索
    print("\n=== 步骤 3: 测试检索 ===")
    test_queries = [
        "使用 DNS 隧道进行 C2 通信",
        "TLS 加密的 Beacon 通信",
        "非标准端口的长连接",
    ]
    
    for query in test_queries:
        print(f"\n查询: {query}")
        results = kb.search(query, top_k=3)
        for i, result in enumerate(results, 1):
            print(f"  {i}. {result['name']} (相似度: {result['score']:.3f})")
            print(f"     C2 技术: {', '.join(result['metadata']['c2_techniques'][:5])}")
    
    # 导出知识库
    print("\n=== 步骤 4: 导出知识库 ===")
    kb.export_to_json("./knowledge_base_export.json")
    
    # 统计信息
    print("\n=== 知识库统计 ===")
    stats = kb.get_stats()
    for key, value in stats.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
