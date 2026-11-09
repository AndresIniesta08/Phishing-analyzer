"""Locate the deployed application root and start the web app."""

from __future__ import annotations

import os
from pathlib import Path
import sys


REQUIRED_APPLICATION_FILES = (
    "web_app.py",
    "email_analysis.py",
    "phishing_analyzer.py",
    "requirements.txt",
    "web/index.html",
    "web/app.js",
    "web/login.html",
    "web/login.js",
    "web/styles.css",
)
_IGNORED_DIRECTORIES = {".git", ".venv", "__pycache__", "node_modules", "venv"}
_MAX_SEARCH_DEPTH = 4


def _is_application_root(path: Path) -> bool:
    return all((path / relative_path).is_file() for relative_path in REQUIRED_APPLICATION_FILES)


def _find_application_root(search_root: Path) -> Path:
    search_root = search_root.resolve()
    if _is_application_root(search_root):
        return search_root

    candidates: list[Path] = []
    for current, directories, files in os.walk(search_root):
        current_path = Path(current)
        depth = len(current_path.relative_to(search_root).parts)
        directories[:] = sorted(
            directory for directory in directories
            if directory not in _IGNORED_DIRECTORIES and depth < _MAX_SEARCH_DEPTH
        )
        if "web_app.py" in files and _is_application_root(current_path):
            candidates.append(current_path)

    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        choices = ", ".join(str(candidate) for candidate in candidates)
        raise RuntimeError(f"Multiple application roots were found; configure one explicitly: {choices}")
    raise FileNotFoundError(
        f"Could not find the phishing analyzer application under {search_root}. "
        "Deploy the project root, including web_app.py, requirements.txt, and the web/ folder."
    )


def main() -> None:
    launcher_directory = Path(__file__).resolve().parent
    application_root = _find_application_root(launcher_directory)
    port = os.environ.get("PORT") or os.environ.get("WEBSITES_PORT") or "8000"
    try:
        parsed_port = int(port)
    except ValueError as exc:
        raise SystemExit("PORT or WEBSITES_PORT must be a valid TCP port number.") from exc
    if not 0 < parsed_port < 65536:
        raise SystemExit("PORT or WEBSITES_PORT must be between 1 and 65535.")

    os.chdir(application_root)
    os.execv(
        sys.executable,
        [sys.executable, str(application_root / "web_app.py"), "--port", str(parsed_port)],
    )


if __name__ == "__main__":
    main()
