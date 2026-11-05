.PHONY: images app test demo clean
images:        ## build the sandbox + sinkhole images
	docker build -t tq-sandbox:latest sandbox/
	docker build -t tq-sinkhole:latest sinkhole/
app:           ## run the web UI locally on :8000
	uvicorn tq.server:app --reload --port 8000
test:          ## run the test suite
	pytest -q
demo:          ## run all three sample tools through the CLI
	python -m tq.cli run samples 'python /tool/unit_converter.py' --name unit-converter
	python -m tq.cli run samples 'python /tool/notes_search.py'   --name notes-search
	python -m tq.cli run samples 'python /tool/json_formatter.py' --name json-formatter
clean:
	docker ps -aq --filter name=tq-box- | xargs -r docker rm -f
	docker ps -aq --filter name=tq-sink- | xargs -r docker rm -f
	docker network ls -q --filter name=tq-net- | xargs -r docker network rm
