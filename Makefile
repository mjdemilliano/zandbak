.PHONY: test check fix
test:
	uv run pytest

check:
	uv run ruff format
	uv run ruff check
	uv run mypy

fix:
	uv run ruff check --fix

