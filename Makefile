.PHONY: setup-learner setup-contributor test notebook-check

setup-learner:
	python3 -m venv .venv
	.venv/bin/python3 -m pip install --upgrade pip
	.venv/bin/pip install -e '.[learner]'

setup-contributor: setup-learner
	.venv/bin/pip install -e '.[contributor]'
	npm ci

test:
	PYTHONPATH=. pytest -q

notebook-check:
	PYTHONPATH=. .venv/bin/python scripts/execute-notebooks.py --timeout 90
