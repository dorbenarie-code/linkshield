# Makefile for LinkShield Project

.PHONY: run-main run-all-scripts test lint check clean

# Run main script
run-main:
	@echo "▶️ Running main.py"
	@python main.py

# Run all scripts in scripts/ folder
run-all-scripts:
	@echo "▶️ Running all scripts in scripts/"
	@for file in scripts/*.py; do \
		echo "➡️ Running $$file"; \
		python "$$file" || echo "❌ Error in $$file"; \
		echo "----"; \
	done

# Run unit tests
test:
	@echo "🧪 Running tests with pytest"
	@pytest tests/

# Run flake8 linter
lint:
	@echo "🔍 Running flake8 linting"
	@flake8 app scripts tests main.py

# Verify all scripts and tests pass
check: lint test run-all-scripts
	@echo "✅ All checks passed!"

# Clean up pycache and reports
clean:
	@echo "🧹 Cleaning __pycache__ and old reports"
	@find . -type d -name "__pycache__" -exec rm -r {} +
	@rm -f reports/*.html reports/*.pdf
