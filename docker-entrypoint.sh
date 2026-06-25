#!/bin/bash
set -euo pipefail

WORKERS=${WORKERS:-1}
ACCESS_LOG=${ACCESS_LOG:--}
ERROR_LOG=${ERROR_LOG:--}
WORKER_TEMP_DIR=${WORKER_TEMP_DIR:-/dev/shm}

echo "Waiting for PostgreSQL..."

until pg_isready -h securevault_secure_db -p 5432 -U securevault
do
  echo "PostgreSQL unavailable - retrying in 2 seconds..."
  sleep 2
done

echo "PostgreSQL is ready!"

# Run migrations
echo "Running database migrations..."
cd /opt/securevault
flask db upgrade

echo "Database migrations completed."

echo "Starting SecureVault..."

exec gunicorn 'app:create_app()' \
    --bind '0.0.0.0:8000' \
    --workers "$WORKERS" \
    --worker-tmp-dir "$WORKER_TEMP_DIR" \
    --access-logfile "$ACCESS_LOG" \
    --error-logfile "$ERROR_LOG"
