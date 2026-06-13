import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.api.app import create_app
from app.api.dependencies import set_repository
from app.repositories.memory_repository import InMemoryRepository


ROOT = Path(__file__).resolve().parents[2]


class DeploymentPhase12Tests(unittest.TestCase):
    def setUp(self):
        set_repository(InMemoryRepository())
        self.client = TestClient(create_app())

    def tearDown(self):
        set_repository(None)

    def test_readiness_reports_memory_by_default(self):
        with patch.dict("os.environ", {"CREDHUNTER_MONGODB_URI": ""}, clear=False):
            response = self.client.get("/health/ready")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ready", "storage": "memory"})

    def test_deployment_assets_exist(self):
        expected_paths = [
            ROOT / "docker-compose.yml",
            ROOT / ".github/workflows/docker-image.yml",
            ROOT / "backend/Dockerfile",
            ROOT / "backend/.dockerignore",
            ROOT / "backend/doc/phase-12/deployment-process.md",
        ]

        for path in expected_paths:
            with self.subTest(path=path):
                self.assertTrue(path.exists(), f"{path} should exist")

    def test_docker_compose_declares_required_services(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

        for service in ["api:", "mongodb:", "redis:", "worker:"]:
            with self.subTest(service=service):
                self.assertIn(service, compose)

        self.assertIn("CREDHUNTER_MONGODB_URI", compose)
        self.assertIn("/health/ready", compose)

    def test_github_action_uses_existing_backend_directory(self):
        action = (ROOT / ".github/actions/credhunter-x/action.yml").read_text(encoding="utf-8")

        self.assertIn("working-directory: backend", action)
        self.assertNotIn("working-directory: Backend", action)

    def test_docker_workflow_runs_tests_before_publishing(self):
        workflow = (ROOT / ".github/workflows/docker-image.yml").read_text(encoding="utf-8")

        self.assertIn("python -m unittest discover -s tests", workflow)
        self.assertIn("docker/build-push-action", workflow)
        self.assertIn("push: ${{ github.event_name != 'pull_request' }}", workflow)


if __name__ == "__main__":
    unittest.main()
