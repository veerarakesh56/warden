PY ?= .venv/Scripts/python.exe
export WARDEN_MOCK ?= 1

.PHONY: demo test evals lint check docker clean

demo:            ## run every bundled incident through the graph
	$(PY) -m warden.cli demo --verbose

run:             ## run one incident: make run INCIDENT=inc-003
	$(PY) -m warden.cli run --incident $(or $(INCIDENT),inc-001) --verbose

test:            ## unit tests only
	$(PY) -m pytest tests -q

evals:           ## the behavioural gate - routing, policy, redaction
	$(PY) -m pytest evals -q

lint:
	$(PY) -m ruff check src tests evals

check: lint test evals  ## what CI runs

docker:
	docker compose up --build

clean:
	rm -rf .pytest_cache **/__pycache__ dist build
