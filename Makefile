.RECIPEPREFIX = >
.PHONY: venv setup test test-docker run-backend run-mock
PY = .venv/bin/python
TOKEN ?= dev-token

venv:
> python3.12 -m venv .venv
> $(PY) -m pip install -U pip
> $(PY) -m pip install -r backend/requirements.txt

setup:
> bash scripts/check_env.sh

test:
> $(PY) -m pytest -m 'not docker' -q

test-docker:
> $(PY) -m pytest -m docker -q -s

run-backend:
> BUILDGUARD_TOKEN=$(TOKEN) $(PY) -m uvicorn backend.main:app --host 127.0.0.1 --port 8787

run-mock:
> $(PY) -m uvicorn backend.mock_server:app --host 127.0.0.1 --port 8787
