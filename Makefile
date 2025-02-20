setup:
	poetry install

test:
	poetry run pytest .\tests\test.py

run:
	poetry run python .\api.py