.PHONY: help install test benchmark run docker-build docker-up clean

PYTHON := .venv/bin/python3
PYTEST := .venv/bin/pytest

help:
	@echo "ULPF Developer Commands:"
	@echo "  make install     - Setup virtualenv and install dependencies"
	@echo "  make test        - Run automated pytest suite"
	@echo "  make benchmark   - Run EPS and latency benchmark"
	@echo "  make run         - Launch Web UI & REST server"
	@echo "  make docker-up   - Start container stack via docker-compose"
	@echo "  make clean       - Remove cached files and build artifacts"

install:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt

test:
	PYTHONPATH=src $(PYTEST) -v

benchmark:
	$(PYTHON) benchmarks/benchmark_throughput.py 10000

run:
	$(PYTHON) ulpf serve --host 0.0.0.0 --port 8000

docker-build:
	docker build -t ulpf:latest .

docker-up:
	docker compose up -d

clean:
	rm -rf .pytest_cache __pycache__ src/**/__pycache__ tests/__pycache__ data/*.db data/*.jsonl data/parquet/*
