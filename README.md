# API Server

This is a simple API server written in Python. It provides two endpoints: `online_score` and `clients_interests`.

## Endpoints

### online_score

This endpoint calculates a score based on the provided data. It takes the following parameters:

* `phone`: phone number
* `email`: email address
* `birthday`: birthday in YYYY-MM-DD format
* `gender`: gender (0 - unknown, 1 - male, 2 - female)
* `first_name`: first name
* `last_name`: last name

It returns a score as a JSON response.

### clients_interests

This endpoint returns the interests of a list of clients. It takes the following parameter:

* `client_ids`: a list of client IDs
* `date`: date in YYYY-MM-DD format

It returns a list of interests as a JSON response.

## Setting up dependencies

To set up the dependencies, use the Makefile:

```bash
make setup
``` 

## Running the Server

To run the server, use the Makefile:

```bash
make run
```
This will start the server on port 8080. You can specify a different port by using the -p flag:

```bash
make run -p 8000
```
You can also run the server with logging enabled by specifying a log file:

```bash
make run -l log.txt
```
This will write log messages to the specified file.

## Testing the Server

To test the server, use the Makefile:

```bash
make test
``` 

This will run the tests and generate a coverage report.