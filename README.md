
# IoC Enrichment 

Hello everyone! In this project, we are working on IoC (Indicator of Compromise) enrichment. We analyze IoCs obtained through an API on various sources and store the collected data in a database. The project aims to perform IoC analysis using different sources and methods, and manage the analysis processes asynchronously.

## Project Features

- Supports analysis on a minimum of 10 different sources for IoC enrichment.
- Runs analysis processes asynchronously.
- Provides a `/search` endpoint to retrieve IoC types.

## Technologies Used

- Python 3.11
- PostgreSQL
- FastAPI 
- SQLAlchemy ORM 
- Docker Compose
- Poetry (https://python-poetry.org/)

## How to Use

1. Open a terminal in the project's root directory.
2. Install the required dependencies first:

   ```bash
   poetry install
3.Start the database:
  docker-compose up -d
4.Run the FastAPI server:
  poetry run uvicorn main:app --host 0.0.0.0 --port 8000
5.Access http://localhost:8000 in your browser or API testing tools.

## Example Usage

You can use the /search endpoint to analyze IoCs. Example request:

GET /search/?q=192.168.1.1

This request will analyze the provided IoC and return the results.

## Development Process
During development, you can follow these steps:
  1-Go to the project folder and start developing.
  2-Add new analysis methods to the relevant files in the scan folder.
  3-Add data you want to save to the database to the appropriate model files in the database folder.
  4-Use the asyncio and async/await structure to manage analysis processes asynchronously.
  5-Record any output using logging instead of print.

## Conclusion

Congratulations! By the end of this challenge, you will have developed a powerful IoC enrichment tool that can perform analysis across various sources and store the enriched data in a PostgreSQL database.
