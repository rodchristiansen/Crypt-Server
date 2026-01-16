#!/bin/bash
# Script to run both Django and Go versions side-by-side for UI comparison

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Encryption key (same for both for testing)
export FIELD_ENCRYPTION_KEY="jKAv1Sde8m6jCYFnmps0iXkUfAilweNVjbvoebBrDwg="
export SESSION_KEY="test-session-key-32-bytes-long!!"
export SQLITE_PATH="${PROJECT_ROOT}/test-go.db"

echo "========================================"
echo "Crypt Server UI Comparison"
echo "========================================"
echo ""
echo "This script will help you compare the Django and Go versions."
echo ""

# Check which server to run
case "${1:-}" in
  django)
    echo "Starting Django server on port 8000..."
    cd "${PROJECT_ROOT}/legacy"

    # Create virtual environment if needed
    if [ ! -d "venv" ]; then
        echo "Creating Python virtual environment..."
        python3 -m venv venv
    fi

    source venv/bin/activate
    pip install -q -r setup/requirements.txt

    # Initialize database
    python manage.py migrate

    # Create test admin user if it doesn't exist
    echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.filter(username='admin').exists() or User.objects.create_superuser('admin', 'admin@example.com', 'password')" | python manage.py shell

    # Create test data
    python manage.py shell <<EOF
from server.models import Computer, Secret
if not Computer.objects.filter(serial='TEST001').exists():
    c = Computer.objects.create(serial='TEST001', username='testuser', computername='Test MacBook Pro')
    Secret.objects.create(computer=c, secret_type='recovery_key', secret='test-recovery-key-12345')
    print("Created test computer and secret")
EOF

    echo ""
    echo "Django server starting on http://localhost:8000"
    echo "Login: admin / password"
    echo ""
    python manage.py runserver 0.0.0.0:8000
    ;;

  go)
    echo "Starting Go server on port 8080..."
    cd "${PROJECT_ROOT}"

    # Build the server
    go build -o crypt-server-test ./cmd/crypt-server

    # Remove old test database
    rm -f "${SQLITE_PATH}"

    # Create initial admin user
    ./crypt-server-test -create-admin -admin-username=admin -admin-password=password

    echo ""
    echo "Go server starting on http://localhost:8080"
    echo "Login: admin / password"
    echo ""
    ./crypt-server-test
    ;;

  both)
    echo "Starting both servers..."
    echo ""
    echo "Django on port 8000: ./scripts/run-comparison.sh django"
    echo "Go on port 8080: ./scripts/run-comparison.sh go"
    echo ""
    echo "Run each command in a separate terminal window."
    ;;

  *)
    echo "Usage: $0 [django|go|both]"
    echo ""
    echo "Commands:"
    echo "  django  - Run Django server on port 8000"
    echo "  go      - Run Go server on port 8080"
    echo "  both    - Show instructions for running both"
    echo ""
    echo "To compare, run in two separate terminals:"
    echo "  Terminal 1: $0 django"
    echo "  Terminal 2: $0 go"
    echo ""
    echo "Then open two browser tabs:"
    echo "  Django: http://localhost:8000"
    echo "  Go:     http://localhost:8080"
    echo ""
    echo "Login credentials: admin / password"
    ;;
esac
