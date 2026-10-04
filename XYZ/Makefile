.PHONY: install run test init smoke docker
PYTHON ?= python3
install:
	$(PYTHON) -m venv .venv
	.venv/bin/python -m pip install -r requirements.txt
run:
	$(PYTHON) run.py
test:
	$(PYTHON) run.py test
init:
	$(PYTHON) run.py init
smoke:
	$(PYTHON) run.py smoke
docker:
	docker compose up --build
