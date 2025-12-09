<!-- .github/copilot-instructions.md - Project-specific guidance for AI coding agents -->

# Phishing Detector — Copilot Instructions

Purpose: give an AI coding agent immediate, actionable knowledge to be productive in this repository.

Quick summary
- Small Python Flask-based service in `app/` that exposes a rule-based URL analyzer.
- The codebase is intentionally minimal: most logic lives in `app/detector.py`.
- There are placeholder modules for future ML integration: `app/ml_model.py` and `app/models.py`.

Big picture (what to know)
- `app/api.py` — a tiny Flask app exposing `/health` and `/analyze` endpoints. It calls `analyze_url` from `app/detector.py`.
- `app/detector.py` — the core: feature extraction (`extract_features`), heuristics (`check_suspicious_patterns`), confidence scoring (`calculate_confidence`) and `get_warnings`.
- Tests are currently empty: `tests/test_detector.py` is present but has no assertions yet.
- Notebooks and training artifacts are minimal/empty; `notebooks/model_training.ipynb` exists as a placeholder.

How to run locally (PowerShell, using the repo venv)
- Activate virtualenv (example from this workspace):
```
& C:/Users/fatih/projelerim/phishing-detector/venv/Scripts/Activate.ps1
```
- Run the API from repository root (PowerShell):
```
# $env:PYTHONPATH = 'app'  # ensures `from detector import ...` works when running from repo root
$env:PYTHONPATH = 'app'; python .\app\api.py
```
Notes: `app/api.py` uses `from detector import analyze_url` (a top-level import). Either run with `cwd=app` or set `PYTHONPATH=app` as shown.

API contract and examples
- POST `/analyze` expects JSON `{ "url": "https://example.com" }`.
- Response shape (example returned by `analyze_url`):
```
{
  "url": "https://...",
  "is_phishing": false,
  "confidence": 12,
  "features": { "url_length": 45, "has_https": true, ... },
  "warnings": ["Not using HTTPS"]
}
```

Key conventions and patterns (project-specific)
- Single-file detector: follow `extract_features` -> `check_suspicious_patterns` -> `calculate_confidence` pattern for new detectors.
- Feature dict keys are canonical (examples in `extract_features`): `url_length`, `domain_length`, `has_ip`, `has_at_symbol`, `num_dots`, `num_hyphens`, `num_underscores`, `has_https`, `num_subdomains`.
- Docstrings and inline comments are in Turkish in `app/detector.py`; retain existing wording when editing unless asked to translate.
- Keep public API stable: `analyze_url(url)` returns the dict shape above; avoid renaming top-level keys without coordinating tests and the API layer.
- Minimal dependencies: `requirements.txt` lists Flask and small libs — avoid adding heavy runtime deps without justification.

Integration points for future work
- `app/ml_model.py` and `app/models.py` are intended for ML model wrappers / persistence. If you add an ML classifier:
  - Provide a thin wrapper function (e.g. `predict(features)`) and call it from `analyze_url` while preserving the existing response shape.
  - Add model artifacts to `.gitignore` and place training code in `notebooks/` or a new `training/` folder.

Testing and CI notes
- Tests are minimal/empty. Create tests under `tests/` and follow current naming (`test_*.py`). Use `pytest`.
- When adding CI, run `pip install -r requirements.txt` and then `pytest`.

For AI agents: rules for edits
- Make small, focused changes; update or add tests for behavioral changes.
- Preserve `analyze_url` response keys unless explicitly changing API. If changing, update `app/api.py` and add tests.
- If fixing imports, prefer minimal changes: either set `PYTHONPATH` in run instructions or convert `app/api.py` to a package import (`from app.detector import analyze_url`) and update `if __name__ == '__main__'` run instructions.
- Do not introduce external services or heavy infra without an explicit task and tests.

Where to look first for common tasks
- To update detection heuristics: edit `app/detector.py`.
- To add an ML model or persistence: edit `app/ml_model.py` and `app/models.py`.
- To add endpoints or change API behavior: edit `app/api.py` and update tests in `tests/`.

If anything is unclear or you want me to expand specific sections (run commands, testing workflow, or an example PR patch), tell me which part to improve.
