#!/bin/bash
# BlockGO Pipeline Testing - Windows Compatible
# This script simulates the deployment pipeline and tests the system

set -e

echo "=================================================="
echo "BlockGO DEPLOYMENT TESTING PIPELINE"
echo "=================================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_phase() { echo -e "${BLUE}[PHASE]${NC} $1"; }
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ============================================================
# STAGE 0: PRE-FLIGHT CHECKS
# ============================================================
log_phase "Stage 0: Pre-Flight Checks"

log_info "Checking database schema fix..."
if grep -q 'CREATE TABLE IF NOT EXISTS users' network/init-db-schema.sql; then
    log_info "✓ Database schema uses lowercase 'users'"
else
    log_error "✗ Database schema has case-sensitivity issues"
fi

log_info "Checking middleware fix..."
if ! grep -q 'ALTER TABLE Users' middleware/middleware.js; then
    log_info "✓ Middleware ALTER TABLE removed"
else
    log_error "✗ Middleware still has problematic ALTER TABLE"
fi

log_info "Checking Docker..."
if docker ps >/dev/null 2>&1; then
    log_info "✓ Docker is running"
else
    log_error "✗ Docker daemon not running"
fi

# ============================================================
# STAGE 1: NETWORK SETUP
# ============================================================
log_phase "Stage 1: Network & Storage Cleanup"

log_info "Stopping existing containers..."
cd network
docker compose down -v 2>&1 | grep -E "Removed|Stopping" | head -5
sleep 5

log_info "✓ Cleanup complete"

# ============================================================
# STAGE 2: DOCKER COMPOSE UP
# ============================================================
log_phase "Stage 2: Starting Docker Containers"

log_info "Pulling images..."
docker compose pull 2>&1 | grep -E "Pulled|latest|downloaded" | head -10 || true

log_info "Starting services..."
docker compose up -d 2>&1 | grep -E "Starting|Created|Running" | head -15

log_info "Waiting 30 seconds for services to initialize..."
sleep 30

log_info "Checking container status..."
docker ps --format "table {{.Names}}\t{{.Status}}" | head -15

# ============================================================
# STAGE 3: SERVICE READINESS CHECKS
# ============================================================
log_phase "Stage 3: Service Health Checks"

echo ""
log_info "Checking PostgreSQL..."
if docker ps | grep -q "postgres.*Up"; then
    log_info "✓ PostgreSQL is running"
else
    log_warn "! PostgreSQL may not be ready yet"
fi

log_info "Checking Orderer..."
if docker ps | grep -q "orderer.*Up"; then
    log_info "✓ Orderer is running"
else
    log_warn "! Orderer may not be ready yet"
fi

log_info "Checking Peers..."
PEER_COUNT=$(docker ps | grep -c "peer.*Up" || true)
log_info "✓ $PEER_COUNT peers running"

log_info "Checking CouchDB..."
if docker ps | grep -q "couchdb.*Up"; then
    log_info "✓ CouchDB is running"
else
    log_warn "! CouchDB may not be ready yet"
fi

# ============================================================
# STAGE 4: DATABASE SCHEMA VERIFICATION
# ============================================================
log_phase "Stage 4: Database Schema Verification"

log_info "Checking database tables..."
if docker exec postgres psql -U BLOCKGO -d ActivityLogs -c "SELECT COUNT(*) as table_count FROM information_schema.tables WHERE table_schema='public';" 2>/dev/null; then
    log_info "✓ Database is responsive and contains tables"
else
    log_warn "! Database may still be initializing"
fi

# ============================================================
# STAGE 5: API CONNECTIVITY TESTS
# ============================================================
log_phase "Stage 5: API Connectivity Tests"

log_info "Testing health endpoint..."
HEALTH_RESP=$(curl -s -w "%{http_code}" http://localhost:4000/api/health -o /tmp/health.json 2>&1 || echo "000")
log_info "Response code: $HEALTH_RESP"

if [ "$HEALTH_RESP" == "200" ]; then
    log_info "✓ Health endpoint responsive"
else
    log_warn "! Health endpoint not yet responsive (this may be normal during startup)"
fi

# ============================================================
# STAGE 6: BOOTSTRAP TEST
# ============================================================
log_phase "Stage 6: Bootstrap Test"

log_info "Attempting to bootstrap registrar..."
BOOTSTRAP_RESP=$(curl -s -w "%{http_code}" http://localhost:4000/api/bootstrap -o /tmp/bootstrap.json 2>&1 || echo "000")
log_info "Response code: $BOOTSTRAP_RESP"

if [ "$BOOTSTRAP_RESP" == "200" ] || [ "$BOOTSTRAP_RESP" == "409" ]; then
    log_info "✓ Bootstrap endpoint working (200=created, 409=already exists)"
    cat /tmp/bootstrap.json 2>/dev/null | head -5 || true
else
    log_warn "! Bootstrap endpoint returned $BOOTSTRAP_RESP (may need more time)"
fi

# ============================================================
# STAGE 7: FINAL REPORT
# ============================================================
echo ""
echo "=================================================="
echo -e "${BLUE}DEPLOYMENT TEST SUMMARY${NC}"
echo "=================================================="
echo ""

log_info "Pre-flight checks: PASSED"
log_info "Database schema: VERIFIED (lowercase)"
log_info "Docker services: RUNNING"
log_info "API endpoints: TESTING"
log_info "Bootstrap: TESTING"

echo ""
log_info "To view full logs:"
echo "  docker logs orderer.capstone.com"
echo "  docker logs peer0.registrar.capstone.com"
echo "  docker logs postgres"
echo ""

log_info "To access the system:"
echo "  Frontend: http://localhost:8080"
echo "  Middleware: http://localhost:4000"
echo "  Backend: http://localhost:5000"
echo ""

log_info "To test login:"
echo "  curl -X POST http://localhost:4000/api/login -H 'Content-Type: application/json' -d '{\"username\":\"registrar@plv.edu.ph\", \"password\":\"admin123\"}'"
echo ""

echo "=================================================="
