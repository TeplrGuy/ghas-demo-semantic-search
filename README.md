---
title: GHAS Demo Project - Semantic Search
description: Demo application for evaluating GitHub Advanced Security scanning capabilities against ML model workloads
ms.date: 2026-04-02
---

# GHAS Demo Project: Semantic Search with all-mpnet-base-v2

A purpose-built demo application that uses the Hugging Face model
[sentence-transformers/all-mpnet-base-v2](https://huggingface.co/sentence-transformers/all-mpnet-base-v2)
to showcase what GitHub Advanced Security (GHAS) can and cannot detect when scanning
ML/AI workloads.

## Background

> **Customer request (verbatim):**
> "Please find the hugging face model we are using and needs malware / vulnerability
> scans - <https://huggingface.co/sentence-transformers/all-mpnet-base-v2>"

This project was created to answer that question directly. The application code contains
intentional security vulnerabilities so GHAS features have real findings to surface.
A separate ModelScan workflow scans the model weights themselves.

## Project Architecture

```text
ghas-demo-project/
├── app.py                  # Flask web app (routes, model loading, search UI)
├── config.py               # App configuration and constants
├── data_processing.py      # Data loading, cleaning, and transformation utilities
├── embedding_service.py    # EmbeddingService class (encode, similarity, export)
├── model_pipeline.py       # ModelPipeline class (download, train, evaluate, export)
├── requirements.txt        # Python dependencies (pinned with known CVEs for demo)
└── .github/
    └── workflows/
        ├── codeql.yml              # CodeQL code scanning (GHAS)
        ├── dependency-review.yml   # Dependency review on PRs (GHAS)
        └── modelscan.yml           # ModelScan for ML model weight scanning
```

### Component Overview

| File | Purpose |
|------|---------|
| `app.py` | Flask application with REST API and web UI. Loads `all-mpnet-base-v2`, stores document embeddings in SQLite, and serves semantic search. Contains intentional vulns (XSS, command injection, SSRF, pickle deserialization, eval, path traversal). |
| `config.py` | Centralized configuration. Contains a hardcoded encryption key for GHAS secret scanning to detect. |
| `data_processing.py` | Text cleaning, dataset loading, and batch processing utilities. Contains unsafe pickle/YAML deserialization, command injection, and eval vulns. |
| `embedding_service.py` | `EmbeddingService` class wrapping sentence-transformers. Handles encoding, similarity, model I/O. Contains SSRF, pickle, path traversal, and MD5 vulns. |
| `model_pipeline.py` | `ModelPipeline` class for end-to-end ML workflows. Contains SSRF, command injection, unsafe deserialization, and XXE vulns. |
| `requirements.txt` | Dependencies pinned to older versions with known CVEs (`flask==2.2.2`, `requests==2.28.0`, `urllib3==1.26.5`) for Dependabot to flag. |

### Model Details

| Property | Value |
|----------|-------|
| Model | `sentence-transformers/all-mpnet-base-v2` |
| Base model | `microsoft/mpnet-base` |
| Embedding dimensions | 768 |
| Max sequence length | 384 |
| Pooling | Mean |
| Source | [Hugging Face Hub](https://huggingface.co/sentence-transformers/all-mpnet-base-v2) |

## Security Scanning Coverage

### What GHAS Detects (Application Code)

GHAS excels at scanning the **application code** and **dependencies** surrounding the model.

**Code Scanning (CodeQL)** catches vulnerabilities in the Python source:

- Unsafe deserialization (`pickle.load` on untrusted input)
- Command injection (`subprocess.run` with `shell=True` and user input)
- Server-Side Request Forgery (SSRF via `requests.get` on user URLs with `verify=False`)
- Code injection (`eval()` on user-controlled strings)
- Unsafe YAML loading (`yaml.load` without `SafeLoader`)
- Cross-site scripting (XSS via string concatenation into HTML)
- Path traversal (user-controlled filenames in file writes)
- Regular expression denial of service (ReDoS)
- Use of broken cryptographic hash (MD5)

**Dependabot** flags known CVEs in pinned dependencies:

- `flask==2.2.2`, `Werkzeug==2.2.2`, `requests==2.28.0`, `urllib3==1.26.5`

**Secret Scanning** detects hardcoded credentials:

- Hardcoded encryption key in `config.py`

**Dependency Review** blocks PRs that introduce new vulnerable dependencies.

### What GHAS Does Not Detect (Model Weights)

GHAS **cannot** inspect model weight files for:

- Malicious payloads embedded in pickle-serialized weights
- Backdoored or poisoned model parameters
- Trojan triggers in fine-tuned models
- Supply chain tampering of model binaries

This is not a limitation specific to this model. GHAS was designed for source code
and package dependencies, not binary ML artifacts.

### Filling the Gap: ModelScan

The `modelscan.yml` workflow uses [Protect AI ModelScan](https://github.com/protectai/modelscan)
to scan the actual model weight files. It:

1. Downloads `sentence-transformers/all-mpnet-base-v2` from Hugging Face Hub
2. Scans all weight files for unsafe serialization patterns
3. Generates a SARIF report and uploads it to the GitHub Security tab
4. Stores JSON and SARIF artifacts for audit

**Result:** The model passes clean. It uses safetensors format, which is inherently
safe (no arbitrary code execution on load).

### Scan Coverage Summary

| Scan Type | Tool | Target | Findings |
|-----------|------|--------|----------|
| Code scanning | CodeQL | Python source files | Multiple (intentional vulns) |
| Dependency scanning | Dependabot | `requirements.txt` | Multiple (pinned old versions) |
| Secret scanning | GHAS Secret Scanning | All files | Hardcoded key in `config.py` |
| Dependency review | `dependency-review-action` | PR dependency changes | Blocks on moderate+ severity |
| Model weight scanning | ModelScan | `all-mpnet-base-v2` weights | Clean (safetensors format) |

## GitHub Actions Workflows

### `codeql.yml` - Code Scanning

Runs CodeQL with the `security-extended` query suite on every push, PR, and weekly
schedule. Results appear in the repository **Security > Code scanning alerts** tab.

### `dependency-review.yml` - Dependency Review

Runs on pull requests. Blocks merges when new dependencies introduce moderate or
higher severity vulnerabilities or use GPL-3.0/AGPL-3.0 licenses.

### `modelscan.yml` - Model Weight Scanning

Runs on every push and PR. Downloads the model from Hugging Face, scans with
ModelScan, and uploads SARIF results to the Security tab alongside CodeQL findings.
Also stores JSON and SARIF reports as workflow artifacts for 90 days.

## Running Locally

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\Activate.ps1 on Windows

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

The app starts at `http://localhost:5000`.

## Key Takeaway

GHAS provides strong coverage for code-level and dependency-level security in ML
projects. For model weight scanning, complement GHAS with a dedicated tool like
ModelScan. The `sentence-transformers/all-mpnet-base-v2` model itself is clean and
uses the safe safetensors format.
