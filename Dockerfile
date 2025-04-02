FROM python:3.10-slim

WORKDIR /app

# Install Poetry and curl for healthcheck
RUN apt-get update \
    && apt-get install -y curl \
    && pip install poetry

# Copy poetry configuration files
COPY pyproject.toml poetry.lock* ./

# Configure poetry and install dependencies
RUN poetry config virtualenvs.create false \
  && poetry install --no-interaction --no-ansi --no-root -vvv

# Copy the application code
COPY . /app/

# Create necessary directories
RUN mkdir -p /var/cache/vana/docker-images

# Command to run the application
CMD ["poetry", "run", "python", "-m", "refiner"]
