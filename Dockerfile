# Use an official Python runtime as a parent image
FROM python:3.11.4

# Install system dependencies
RUN apt-get update \
    && apt-get install -y curl

# Install poetry
RUN curl -sSL https://install.python-poetry.org/ | python -
ENV PATH="/root/.local/bin:$PATH"

# Set the working directory to /app
WORKDIR /app

# Copy the rest of the application code
COPY . /app

# Configure poetry and install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi

# Set the working directory to /app/src/app
WORKDIR /app/src/api

# Run the command to start the application
CMD ["poetry", "run", "python", "api.py"]

