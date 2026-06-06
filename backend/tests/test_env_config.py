import os
import unittest
from unittest.mock import patch

from app.ci.config import load_config


class EnvConfigTests(unittest.TestCase):
    def test_openai_model_can_be_declared_by_environment(self):
        with patch.dict(
            os.environ,
            {
                "CREDHUNTER_OPENAI_MODEL": "o4-mini",
                "CREDHUNTER_LLM_ENABLED": "true",
            },
            clear=False,
        ):
            config = load_config("tests/fixtures/credhunter.yml")

        self.assertTrue(config.llm.enabled)
        self.assertEqual(config.llm.model, "o4-mini")


if __name__ == "__main__":
    unittest.main()
