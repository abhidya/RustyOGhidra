import json
import logging
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.bridge import Bridge
from src.config import BridgeConfig


class PortPromptRoutingTests(unittest.TestCase):
    def setUp(self):
        with patch("src.bridge.setup_logging", return_value=MagicMock()), patch("src.bridge.OllamaClient"), patch(
            "src.bridge.GhidraMCPClient"
        ):
            self.bridge = Bridge(BridgeConfig(), include_capabilities=False, enable_cag=False)
        self.bridge.set_task_mode(True, "port_1to1")

    def test_all_phases_use_port_specific_prompts(self):
        expected = {
            "planning": "one Borg family and one action index",
            "execution": "CONSTRUCTOR -> DISPATCH -> TABLES -> PHASES",
            "analysis": "port dossier",
            "evaluation": "adversarial verifier",
            "review": "Review the proposed port",
        }
        for phase, needle in expected.items():
            system, _ = self.bridge._build_structured_prompt(phase=phase)
            self.assertIn(needle, system, phase)
            self.assertNotIn("systematic threat hunting", system.lower(), phase)

    def test_valid_dossier_is_captured_atomically(self):
        payload = {
            "version": 1,
            "scope": {"family": "ROBOT", "actionIndex": 0},
            "variants": [],
            "phases": [],
            "claims": [
                {
                    "claimId": "robot.action0.phase0",
                    "status": "DERIVED_ROM",
                    "function": "0x800f1e30",
                    "statement": "Action 0 dispatches through the verified phase table.",
                    "evidence": [{"tier": "authoritative", "source": "boot.dol@800f1e30"}],
                }
            ],
            "blockers": [],
            "tests": [],
        }
        with tempfile.TemporaryDirectory() as folder:
            self.bridge.port_dossiers_dir = folder
            path = self.bridge._capture_port_dossier("```json\n" + json.dumps(payload) + "\n```")
            self.assertIsNotNone(path)
            self.assertTrue(os.path.exists(path))
            self.assertFalse(any(name.endswith(".tmp") for name in os.listdir(folder)))

    def test_port_analysis_bypasses_generic_security_report_pipeline(self):
        expected = "port dossier"
        self.bridge._analyze_for_port = MagicMock(return_value=expected)
        result = self.bridge._analyze_execution_results(MagicMock())
        self.assertEqual(result, expected)
        self.bridge._analyze_for_port.assert_called_once()

    def test_port_evaluation_rejects_missing_or_invalid_dossier_before_llm(self):
        achieved, reason = self.bridge._evaluate_goal_achievement("port action", "plausible prose", MagicMock())
        self.assertFalse(achieved)
        self.assertIn("schema-valid", reason)


if __name__ == "__main__":
    unittest.main()
