.PHONY: install dev test test-e2e deploy smoke marketplace-package

PYTHON ?= python
VENV ?= .venv

install:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/Scripts/pip install -r requirements-dev.txt

dev:
	$(VENV)/Scripts/python -m basilisk.serve --port 8080

test:
	$(VENV)/Scripts/pytest tests/unit tests/integration -q

test-e2e:
	$(VENV)/Scripts/pytest tests/e2e -m e2e -v

deploy:
	powershell -ExecutionPolicy Bypass -File scripts/deploy-azure.ps1

deploy-terraform:
	powershell -ExecutionPolicy Bypass -File scripts/deploy-terraform-cloudshell.ps1

smoke:
	powershell -ExecutionPolicy Bypass -File scripts/smoke-test.ps1

marketplace-package:
	powershell -ExecutionPolicy Bypass -File scripts/package-marketplace.ps1
