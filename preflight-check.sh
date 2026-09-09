#!/bin/bash
# BlockGO Deployment - Pre-Flight Checklist
# Run this before attempting deployment to ensure all fixes are in place

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

check_pass() { echo -e "${GREEN}✓${NC} $1"; }
check_fail() { echo -e "${RED}✗${NC} $1"; exit 1; }
check_warn() { echo -e "${YELLOW}!${NC} $1"; }

echo "=========================================="
echo "BlockGO Deployment - Pre-Flight Checklist"
echo "=========================================="
echo ""

# Check 1: Database Schema
echo "1. Checking database schema..."
if grep -q 'CREATE TABLE IF NOT EXISTS users' network/init-db-schema.sql; then
    check_pass "Database schema uses lowercase 'users' table"
else
    check_fail "Database schema still uses uppercase 'Users' - run fixes first"
fi

# Check 2: Middleware fix
echo "2. Checking middleware.js..."
if ! grep -q 'ALTER TABLE Users' middleware/middleware.js; then
    check_pass "Middleware ALTER TABLE statement removed"
else
    check_fail "Middleware still has problematic ALTER TABLE Users"
fi

if grep -q 'Database schema initialized via init-db-schema.sql' middleware/middleware.js; then
    check_pass "Middleware has correct startup comment"
else
    check_warn "Middleware comment may be missing (non-critical)"
fi

# Check 3: Fix script exists
echo "3. Checking cleanup script..."
if [ -f "network/fix-db-case-sensitivity.sh" ]; then
    check_pass "Database cleanup script exists"
else
    check_warn "Database cleanup script missing (not critical for fresh deploy)"
fi

# Check 4: GitHub Actions workflows
echo "4. Checking GitHub Actions workflows..."
if grep -q 'CREATE TABLE IF NOT EXISTS users' .github/workflows/stress-test.yml; then
    check_pass "stress-test.yml has schema verification"
else
    check_warn "stress-test.yml may need schema verification update"
fi

if grep -q 'CREATE TABLE IF NOT EXISTS users' .github/workflows/tdd-pipeline.yml; then
    check_pass "tdd-pipeline.yml has schema verification"
else
    check_warn "tdd-pipeline.yml may need schema verification update"
fi

# Check 5: Docker setup
echo "5. Checking Docker..."
if docker --version >/dev/null 2>&1; then
    check_pass "Docker is installed"
else
    check_fail "Docker is not installed or not in PATH"
fi

if docker ps >/dev/null 2>&1; then
    check_pass "Docker daemon is running"
else
    check_fail "Docker daemon is not running"
fi

# Check 6: Required scripts
echo "6. Checking deployment scripts..."
if [ -f "network/full_deploy.sh" ] && [ -x "network/full_deploy.sh" ]; then
    check_pass "full_deploy.sh exists and is executable"
else
    check_fail "full_deploy.sh missing or not executable - run: chmod +x network/full_deploy.sh"
fi

# Check 7: Docker Compose
echo "7. Checking docker-compose setup..."
if [ -f "network/docker-compose.yaml" ]; then
    check_pass "docker-compose.yaml exists"
else
    check_fail "docker-compose.yaml not found"
fi

# Summary
echo ""
echo "=========================================="
echo "Pre-Flight Checklist Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. cd network"
echo "2. docker compose down -v        (clean slate)"
echo "3. ./full_deploy.sh              (deploy)"
echo ""
echo "Expected result:"
echo "  [INFO] Registrar bootstrapped successfully!"
echo "  [INFO] Application is now running."
echo "  Access the web application at: http://localhost:8080"
echo ""
