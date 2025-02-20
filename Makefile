setup:
	poetry install

test:
	poetry run pytest .\tests\test.py
