from pathlib import Path
import tempfile
import unittest

from azure_startup import REQUIRED_APPLICATION_FILES, _find_application_root


class AzureStartupTests(unittest.TestCase):
    def test_project_root_contains_all_required_application_files(self) -> None:
        project_root = Path(__file__).parent
        self.assertEqual(_find_application_root(project_root), project_root.resolve())

    def test_finds_application_nested_under_deployment_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment_root = Path(temporary_directory)
            application_root = deployment_root / "Phishing-analyzer-main"
            for relative_path in REQUIRED_APPLICATION_FILES:
                file_path = application_root / relative_path
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.touch()

            self.assertEqual(_find_application_root(deployment_root), application_root.resolve())


if __name__ == "__main__":
    unittest.main()
