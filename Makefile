all: dca

dca:
	@echo "Checking if ls.db exists..."
	[ ! -f "ls.db" ] && Tracer -t sqlite -o ls.db -- ls

	@echo "Running Solver scripts..."
	python3 ./scripts/trace_wyseur.py
	python3 ./scripts/recover.py

clean:
	@echo "Cleaning up temporary files..."
	rm -rf trace.tmp* *.config *.input *.output *.trace *.info
	rm -rf ls.db trace-full-info.txt
	rm -rf ./scripts/__pycache__
	@echo "Clean complete."

.PHONY: all dca clean
