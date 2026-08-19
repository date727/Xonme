"""Validate the optional Chinese attribution display map shipped with the app."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.knowledge_base.vector_db import _load_chinese_display_map, _translated_text


class ChineseKnowledgeMapTests(unittest.TestCase):
    def test_map_contains_resolvable_group_and_technique_translations(self):
        display_map = _load_chinese_display_map()
        translations = display_map.get("translations", {})
        groups = display_map.get("groups", {})

        self.assertTrue(translations, "backend/data/knowledge_base_zh.json is missing or empty")
        self.assertTrue(groups, "Chinese attribution group mappings are missing")

        translated_backgrounds = 0
        translated_techniques = 0
        for group in groups.values():
            if _translated_text(translations, group.get("background")):
                translated_backgrounds += 1
            for technique in group.get("c2_techniques", {}).values():
                fields = technique.get("translations", {})
                if _translated_text(translations, fields.get("name")) and _translated_text(
                    translations, fields.get("relationship_desc")
                ):
                    translated_techniques += 1

        self.assertGreater(translated_backgrounds, 0)
        self.assertGreater(translated_techniques, 0)


if __name__ == "__main__":
    unittest.main()
