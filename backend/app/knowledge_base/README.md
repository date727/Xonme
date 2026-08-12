# MITRE ATT&CK 知识库模块

## 概述

该模块负责解析 MITRE ATT&CK STIX 数据，提取 APT 组织的 TTP（战术、技术、流程），并构建基于向量数据库的语义检索系统，用于威胁溯源归因。

## 核心功能

1. **STIX 数据解析** (`stix_parser.py`)
   - 解析 MITRE ATT&CK STIX 2.1 JSON 格式数据
   - 提取 APT 组织（intrusion-set）、攻击技术（attack-pattern）、恶意软件/工具（malware/tool）
   - 建立组织与技术、工具的映射关系
   - 重点关注 C2 相关技术（T1071, T1573, T1571 等）

2. **向量知识库** (`vector_db.py`)
   - 基于 ChromaDB 的轻量级向量数据库
   - 使用 Sentence Transformers 生成文本 Embedding
   - 支持语义检索和相似度匹配
   - 持久化存储，一次构建多次使用

## 快速开始

### 1. 安装依赖

```bash
cd backend
pip install -r requirements.txt
```

这将安装：
- `chromadb`: 向量数据库
- `sentence-transformers`: 文本 Embedding 模型
- `stix2`: STIX 数据处理（可选，当前使用原生 JSON 解析）

### 2. 构建知识库

使用项目根目录下的 STIX 数据构建知识库：

```bash
cd backend
python build_knowledge_base.py --test-query
```

**可选参数：**
- `--stix-file`: 指定 STIX 文件路径（默认使用最新版 Enterprise ATT&CK）
- `--db-path`: 数据库存储路径（默认 `./chroma_db`）
- `--embedding-model`: Embedding 模型名称（默认 `all-MiniLM-L6-v2`）
- `--export-json`: 导出知识库为 JSON 文件
- `--test-query`: 构建后运行测试查询

**示例：**

```bash
# 使用默认配置
python build_knowledge_base.py

# 指定其他 STIX 文件
python build_knowledge_base.py --stix-file ../attack-stix-data/mobile-attack/mobile-attack-19.1.json

# 使用更好的 Embedding 模型（但会更大更慢）
python build_knowledge_base.py --embedding-model sentence-transformers/all-mpnet-base-v2

# 导出知识库为 JSON
python build_knowledge_base.py --export-json ./apt_knowledge_base.json
```

### 3. 测试解析器（单独测试）

```bash
cd backend/app/knowledge_base
python stix_parser.py ../../../attack-stix-data/enterprise-attack/enterprise-attack-19.1.json
```

### 4. 在代码中使用

```python
from app.knowledge_base import VectorKnowledgeBase

# 初始化知识库（会自动加载已构建的索引）
kb = VectorKnowledgeBase(db_path="./chroma_db")

# 语义检索
query = "使用 DNS 隧道进行 C2 通信的 APT 组织"
results = kb.search(query, top_k=5)

for result in results:
    print(f"组织: {result['name']}")
    print(f"相似度: {result['score']:.3f}")
    print(f"C2 技术: {result['metadata']['c2_techniques']}")
    print(f"URL: {result['metadata']['mitre_url']}")
    print()
```

## 数据结构

### APT 组织档案结构

```python
{
    "group_id": "intrusion-set--...",
    "name": "APT29",
    "aliases": ["Cozy Bear", "The Dukes"],
    "description": "组织描述...",
    "mitre_url": "https://attack.mitre.org/groups/G0016/",
    "all_techniques": [...],  # 所有使用的技术
    "c2_techniques": [...],   # C2 相关技术
    "software": [...],        # 使用的工具
    "technique_count": 50,
    "c2_technique_count": 8,
}
```

### 检索结果结构

```python
{
    "id": "intrusion-set--...",
    "name": "APT29",
    "distance": 0.45,  # L2 距离（越小越相似）
    "score": 0.69,     # 相似度分数 0-1（越大越相似）
    "metadata": {
        "name": "APT29",
        "aliases": [...],
        "mitre_url": "...",
        "c2_techniques": ["T1071.001", "T1573.002"],
        ...
    },
    "text": "完整的组织描述文本..."
}
```

## C2 相关技术列表

当前重点关注以下 MITRE ATT&CK 技术：

- **T1071**: Application Layer Protocol（应用层协议）
  - T1071.001: Web Protocols
  - T1071.002: File Transfer Protocols
  - T1071.003: Mail Protocols
  - T1071.004: DNS
- **T1573**: Encrypted Channel（加密通道）
  - T1573.001: Symmetric Cryptography
  - T1573.002: Asymmetric Cryptography
- **T1571**: Non-Standard Port（非标准端口）
- **T1572**: Protocol Tunneling（协议隧道）
- **T1090**: Proxy（代理）
- **T1095**: Non-Application Layer Protocol（非应用层协议）
- **T1568**: Dynamic Resolution（动态解析）

## Embedding 模型选择

| 模型 | 大小 | 速度 | 质量 | 适用场景 |
|------|------|------|------|----------|
| `all-MiniLM-L6-v2` | 80MB | 快 | 中 | **推荐：原型开发** |
| `all-mpnet-base-v2` | 420MB | 中 | 高 | 生产环境（英文） |
| `paraphrase-multilingual-MiniLM-L12-v2` | 420MB | 中 | 中 | 多语言支持 |
| `BAAI/bge-small-zh-v1.5` | 100MB | 快 | 中 | 中文查询 |
| `BAAI/bge-large-zh-v1.5` | 1.3GB | 慢 | 高 | 中文生产环境 |

## 性能指标

- **构建时间**: ~2-3 分钟（Enterprise ATT&CK 19.1，约 189 个 APT 组织）
- **索引大小**: ~50MB（包含向量和元数据）
- **检索速度**: <100ms（Top-5 查询）
- **内存占用**: ~500MB（加载 Embedding 模型后）

## 故障排除

### 1. 依赖安装失败

```bash
# 如果 sentence-transformers 安装失败，尝试单独安装 PyTorch
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu

# 然后再安装其他依赖
pip install chromadb sentence-transformers
```

### 2. Embedding 模型下载缓慢

模型会自动从 HuggingFace 下载，国内可能较慢。解决方案：

```bash
# 设置 HuggingFace 镜像（国内）
export HF_ENDPOINT=https://hf-mirror.com

# 或手动下载模型到本地，然后指定路径
python build_knowledge_base.py --embedding-model /path/to/local/model
```

### 3. 内存不足

如果内存有限，使用更小的模型：

```bash
python build_knowledge_base.py --embedding-model sentence-transformers/all-MiniLM-L6-v2
```

或者减少批处理大小（修改 `vector_db.py` 中的 `batch_size` 参数）。

## 下一步计划

- [ ] 支持增量更新（不重建整个索引）
- [ ] 添加技术 ID 精确匹配（T1071.001 → 直接返回使用该技术的所有组织）
- [ ] 集成到主 API（`main.py`），提供归因接口
- [ ] 添加缓存机制，提升检索速度
- [ ] 支持多域（Enterprise + Mobile + ICS）联合检索

## 参考资料

- [MITRE ATT&CK](https://attack.mitre.org/)
- [STIX 2.1 规范](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [ChromaDB 文档](https://docs.trychroma.com/)
- [Sentence Transformers](https://www.sbert.net/)
