.PHONY: test demo clean help

help:
	@echo "Available commands:"
	@echo "  make test  - Run all pytest test suites"
	@echo "  make demo  - Run end-to-end automated demonstration script"
	@echo "  make clean - Remove temporary databases and test caches"

test:
	python -m pytest tests/ -v

demo:
	python demo.py

clean:
	rm -rf .pytest_cache backend_inventory.sqlite tickets.json
