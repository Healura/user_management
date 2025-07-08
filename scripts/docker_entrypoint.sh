#!/bin/bash
set -e

echo "Starting Voice Biomarker User Management Service..."

# Wait for database to be ready
echo "Waiting for database..."
while ! nc -z ${RDS_ENDPOINT} ${RDS_PORT}; do
  sleep 1
done
echo "Database is ready!"

# Run migrations
echo "Running database migrations..."
alembic upgrade head

# Initialize roles if needed
echo "Initializing roles..."
python scripts/init_roles.py

# Generate JWT keys if they don't exist
if [ ! -f "./keys/jwt_private_key.pem" ]; then
    echo "Generating JWT keys..."
    python scripts/generate_jwt_keys.py
fi

# Start the application
echo "Starting application..."
exec uvicorn src.main:app --host 0.0.0.0 --port 8000 --workers ${WORKERS:-4}