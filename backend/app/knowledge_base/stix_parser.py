"""
STIX 数据解析器
从 MITRE ATT&CK STIX JSON 文件中提取 APT 组织、技术、工具和关系映射
"""

import json
from pathlib import Path
from typing import Any


class STIXParser:
    """解析 MITRE ATT&CK STIX 数据"""
    
    # 从 STIX 数据自动识别 C2 技术：kill_chain_phases 包含 "command-and-control" 即判定为 C2
    # 不再维护硬编码列表，MITRE 自己已经分类好了
    
    def __init__(self, stix_path: str | Path | None = None, stix_paths: list[str | Path] | None = None):
        """
        初始化 STIX 解析器

        Args:
            stix_path: 单个 STIX JSON 文件路径（向后兼容）
            stix_paths: 多个 STIX JSON 文件路径列表（合并解析）
        """
        self.stix_paths: list[Path] = []
        if stix_path:
            self.stix_paths.append(Path(stix_path))
        if stix_paths:
            self.stix_paths.extend(Path(p) for p in stix_paths)

        self.data: dict[str, Any] = {}
        self.groups: dict[str, dict] = {}  # intrusion-set
        self.techniques: dict[str, dict] = {}  # attack-pattern
        self.software: dict[str, dict] = {}  # malware + tool
        self.relationships: list[dict] = []

    def load_file(self, file_path: Path) -> dict:
        """加载单个 STIX JSON 文件，返回 objects 列表"""
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("objects", [])

    def load(self) -> None:
        """加载所有 STIX JSON 文件并合并"""
        all_objects: list[dict] = []
        for fp in self.stix_paths:
            objects = self.load_file(fp)
            all_objects.extend(objects)
            print(f"✓ 加载: {fp.name} ({len(objects)} 个对象)")
        self.data = {"objects": all_objects}
        print(f"✓ 共加载 {len(self.stix_paths)} 个文件, {len(all_objects)} 个 STIX 对象")

    def parse(self) -> None:
        """解析 STIX 对象，分类存储（支持多文件去重合并）"""
        if not self.data:
            self.load()

        objects = self.data.get("objects", [])
        seen_rels = set()  # 用于关系去重

        for obj in objects:
            obj_type = obj.get("type")
            obj_id = obj.get("id")

            # APT 组织（intrusion-set）
            if obj_type == "intrusion-set":
                if obj_id not in self.groups:
                    self.groups[obj_id] = {
                        "id": obj_id,
                        "name": obj.get("name", "Unknown"),
                        "aliases": obj.get("aliases", []),
                        "description": obj.get("description", ""),
                        "external_references": obj.get("external_references", []),
                    }
                else:
                    # 合并 aliases（可能来自不同领域的补充信息）
                    existing = self.groups[obj_id]
                    existing["aliases"] = list(set(existing["aliases"] + obj.get("aliases", [])))
                    # 优先保留更长的描述
                    new_desc = obj.get("description", "")
                    if len(new_desc) > len(existing["description"]):
                        existing["description"] = new_desc

            # 技术（attack-pattern）
            elif obj_type == "attack-pattern":
                if obj_id not in self.techniques:
                    external_id = self._get_external_id(obj)
                    self.techniques[obj_id] = {
                        "id": obj_id,
                        "technique_id": external_id,
                        "name": obj.get("name", "Unknown"),
                        "description": obj.get("description", ""),
                        "kill_chain_phases": obj.get("kill_chain_phases", []),
                        "external_references": obj.get("external_references", []),
                    }

            # 恶意软件和工具
            elif obj_type in ("malware", "tool"):
                if obj_id not in self.software:
                    self.software[obj_id] = {
                        "id": obj_id,
                        "type": obj_type,
                        "name": obj.get("name", "Unknown"),
                        "description": obj.get("description", ""),
                        "external_references": obj.get("external_references", []),
                    }

            # 关系（需要去重，同一个 (source, target, type) 只保留一条）
            elif obj_type == "relationship":
                rel_key = (
                    obj.get("source_ref", ""),
                    obj.get("target_ref", ""),
                    obj.get("relationship_type", ""),
                )
                if rel_key not in seen_rels:
                    seen_rels.add(rel_key)
                    self.relationships.append({
                        "source_ref": obj.get("source_ref"),
                        "target_ref": obj.get("target_ref"),
                        "relationship_type": obj.get("relationship_type"),
                        "description": obj.get("description", ""),
                    })

        print(f"✓ 解析完成:")
        print(f"  - APT 组织: {len(self.groups)}")
        print(f"  - 攻击技术: {len(self.techniques)}")
        print(f"  - 恶意软件/工具: {len(self.software)}")
        print(f"  - 关系: {len(self.relationships)}")
    
    def build_group_profiles(self) -> dict[str, dict]:
        """
        构建 APT 组织的完整档案
        包含该组织使用的技术和工具
        
        Returns:
            group_id -> 组织档案字典
        """
        if not self.groups:
            self.parse()
            
        profiles = {}
        
        for group_id, group_info in self.groups.items():
            # 查找该组织使用的技术
            used_techniques = []
            used_software = []
            
            for rel in self.relationships:
                # Group -> Technique
                if (rel["source_ref"] == group_id and
                    rel["relationship_type"] == "uses" and
                    rel["target_ref"] in self.techniques):
                    tech = self.techniques[rel["target_ref"]]
                    used_techniques.append({
                        "technique_id": tech["technique_id"],
                        "name": tech["name"],
                        "description": tech["description"],
                        "relationship_desc": rel.get("description", ""),
                        "kill_chain_phases": tech.get("kill_chain_phases", []),
                    })
                    
                # Group -> Software
                elif (rel["source_ref"] == group_id and 
                      rel["relationship_type"] == "uses" and
                      rel["target_ref"] in self.software):
                    sw = self.software[rel["target_ref"]]
                    used_software.append({
                        "name": sw["name"],
                        "type": sw["type"],
                        "description": sw["description"],
                        "relationship_desc": rel.get("description", ""),
                    })
            
            # 筛选 C2 相关技术：kill_chain_phases 包含 "command-and-control"
            c2_techniques = [
                t for t in used_techniques
                if "command-and-control" in (
                    p.get("phase_name", "") for p in t.get("kill_chain_phases", [])
                )
            ]
            
            # 构建档案
            profiles[group_id] = {
                "group_id": group_id,
                "name": group_info["name"],
                "aliases": group_info["aliases"],
                "description": group_info["description"],
                "mitre_url": self._get_mitre_url(group_info),
                "all_techniques": used_techniques,
                "c2_techniques": c2_techniques,
                "software": used_software,
                "technique_count": len(used_techniques),
                "c2_technique_count": len(c2_techniques),
            }
            
        print(f"✓ 构建了 {len(profiles)} 个组织档案")
        return profiles
    
    def build_rag_documents(self) -> list[dict]:
        """
        构建用于 RAG 的文档
        每个 APT 组织生成一个富文本描述文档
        
        Returns:
            文档列表，每个文档包含 id, text, metadata
        """
        profiles = self.build_group_profiles()
        documents = []
        
        for group_id, profile in profiles.items():
            # 只入库有 C2 技术的组织（C2 判定依据 kill_chain_phases）
            if profile["c2_technique_count"] == 0:
                continue

            # 构建富文本描述
            text_parts = [
                f"组织名称: {profile['name']}",
            ]

            if profile["aliases"]:
                text_parts.append(f"别名: {', '.join(profile['aliases'])}")

            text_parts.append(f"\n组织描述:\n{profile['description']}")

            # C2 相关技术详情
            if profile["c2_techniques"]:
                text_parts.append("\n使用的 C2 通信技术:")
                for tech in profile["c2_techniques"]:
                    text_parts.append(
                        f"- {tech['technique_id']} {tech['name']}: "
                        f"{tech['relationship_desc'] or tech['description'][:200]}"
                    )

            # 使用的工具
            if profile["software"]:
                text_parts.append("\n使用的恶意软件/工具:")
                for sw in profile["software"][:10]:  # 限制数量
                    text_parts.append(
                        f"- {sw['name']} ({sw['type']}): "
                        f"{sw['relationship_desc'][:150] if sw['relationship_desc'] else ''}"
                    )
            
            c2_tech_list = [f"{t['technique_id']}" for t in profile["c2_techniques"]]
            aliases_list = profile["aliases"] if profile["aliases"] else ["(none)"]

            document = {
                "id": group_id,
                "text": "\n".join(text_parts),
                "metadata": {
                    "name": profile["name"],
                    "aliases": aliases_list,
                    "mitre_url": profile["mitre_url"],
                    "technique_count": profile["technique_count"],
                    "c2_technique_count": profile["c2_technique_count"],
                    "c2_techniques": c2_tech_list,
                },
            }
            documents.append(document)

        print(f"✓ 生成了 {len(documents)} 个 RAG 文档（C2 判定依据: kill_chain_phases 含 command-and-control）")
        return documents
    
    @staticmethod
    def _get_external_id(obj: dict) -> str:
        """提取 MITRE ATT&CK 技术 ID（如 T1071.001）"""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id", "")
        return ""
    
    @staticmethod
    def _get_mitre_url(group_info: dict) -> str:
        """提取 MITRE ATT&CK 官网 URL"""
        for ref in group_info.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("url", "")
        return ""


def main():
    """测试脚本"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python stix_parser.py <path_to_stix_json>")
        sys.exit(1)
    
    parser = STIXParser(sys.argv[1])
    parser.parse()
    profiles = parser.build_group_profiles()
    
    # 打印前 5 个组织
    print("\n示例组织档案:")
    for i, (group_id, profile) in enumerate(profiles.items()):
        if i >= 5:
            break
        print(f"\n{profile['name']} ({profile['c2_technique_count']} 个 C2 技术):")
        for tech in profile["c2_techniques"][:3]:
            print(f"  - {tech['technique_id']}: {tech['name']}")
    
    # 生成 RAG 文档
    documents = parser.build_rag_documents()
    print(f"\n生成的 RAG 文档数: {len(documents)}")


if __name__ == "__main__":
    main()
