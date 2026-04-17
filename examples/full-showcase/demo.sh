#!/usr/bin/env bash
# Nautilus full-showcase demo script.
#
# Prerequisites: docker compose up --build -d
# Usage: ./demo.sh
set -euo pipefail

API="http://localhost:8000"
KEY="demo-key-2024"

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

section() { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${NC}\n"; }
info()    { echo -e "${GREEN}$1${NC}"; }
warn()    { echo -e "${YELLOW}$1${NC}"; }

# -----------------------------------------------------------------------
section "1. Health check"
# -----------------------------------------------------------------------
echo "GET /healthz"
curl -s "$API/healthz" | python3 -m json.tool
echo ""
echo "GET /readyz"
curl -s "$API/readyz" | python3 -m json.tool

# -----------------------------------------------------------------------
section "2. List configured sources (metadata only — no DSNs exposed)"
# -----------------------------------------------------------------------
echo "GET /v1/sources"
curl -s "$API/v1/sources" | python3 -m json.tool

# -----------------------------------------------------------------------
section "3. Query as 'analyst' (clearance: cui-basic)"
info "Intent: 'Show me critical vulnerability CVEs'"
info "Expected: vuln_db (cui-basic) accessible, compliance_docs (cui-specified) denied"
# -----------------------------------------------------------------------
curl -s -X POST "$API/v1/request" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{
    "agent_id": "analyst",
    "intent": "Show me critical vulnerability CVEs and patches",
    "context": {"session_id": "demo-session-1", "purpose": "threat-analysis"}
  }' | python3 -m json.tool

# -----------------------------------------------------------------------
section "4. Query as 'intern' (clearance: unclassified)"
info "Intent: 'What is the CPU usage on web-01?'"
info "Expected: server_metrics (unclassified) accessible, vuln_db (cui-basic) denied"
# -----------------------------------------------------------------------
curl -s -X POST "$API/v1/request" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{
    "agent_id": "intern",
    "intent": "What is the CPU usage and memory on web-01?",
    "context": {"session_id": "demo-session-2", "purpose": "monitoring"}
  }' | python3 -m json.tool

# -----------------------------------------------------------------------
section "5. Query as 'auditor' (clearance: cui-specified)"
info "Intent: 'Pull the Q1 security audit compliance report'"
info "Expected: all sources accessible at auditor clearance level"
# -----------------------------------------------------------------------
curl -s -X POST "$API/v1/request" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{
    "agent_id": "auditor",
    "intent": "Pull the Q1 security audit compliance report and vulnerability findings",
    "context": {"session_id": "demo-session-3", "purpose": "compliance-audit"}
  }' | python3 -m json.tool

# -----------------------------------------------------------------------
section "6. Demonstrate denied access (intern → cui-specified data)"
warn "Intent: 'Show me the HIPAA compliance audit report'"
warn "Expected: compliance_docs DENIED — intern lacks cui-specified clearance"
# -----------------------------------------------------------------------
curl -s -X POST "$API/v1/request" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{
    "agent_id": "intern",
    "intent": "Show me the HIPAA compliance audit report and policy documents",
    "context": {"session_id": "demo-session-4", "purpose": "compliance-audit"}
  }' | python3 -m json.tool

# -----------------------------------------------------------------------
section "7. Auth failure (missing API key)"
warn "Expected: 403 Forbidden"
# -----------------------------------------------------------------------
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST "$API/v1/request" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "analyst", "intent": "test", "context": {}}'

# -----------------------------------------------------------------------
section "8. Admin UI"
# -----------------------------------------------------------------------
info "Source status page:   $API/admin/sources"
info "Decisions viewer:     $API/admin/decisions"
info "Audit event log:      $API/admin/audit"
info "Attestation verifier: $API/admin/attestation"
echo ""
info "Open your browser to explore the admin dashboard."

# -----------------------------------------------------------------------
section "9. Observability stack"
# -----------------------------------------------------------------------
info "Grafana dashboards:   http://localhost:3000"
info "  - Nautilus Overview: request rate, latency, error rate"
info "  - Adapters:          per-adapter query duration and errors"
info "  - Attestation:       signing latency and verification stats"
echo ""
info "Tempo (traces):       http://localhost:3200"
info "Prometheus (metrics):  http://localhost:9090"
info "Loki (logs):          http://localhost:3100"

# -----------------------------------------------------------------------
section "10. Query as 'analyst' — threat intelligence (Neo4j)"
info "Intent: 'Show me threat actors and their TTPs'"
info "Expected: threat_graph (cui-basic) accessible to analyst"
# -----------------------------------------------------------------------
curl -s -X POST "$API/v1/request" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{
    "agent_id": "analyst",
    "intent": "Show me threat actors and their attack techniques and IOC indicators",
    "context": {"session_id": "demo-session-5", "purpose": "threat-analysis"}
  }' | python3 -m json.tool

# -----------------------------------------------------------------------
section "11. Query as 'analyst' — application logs (Elasticsearch)"
info "Intent: 'Show me recent error logs and exceptions'"
info "Expected: app_logs (cui-basic) accessible to analyst"
# -----------------------------------------------------------------------
curl -s -X POST "$API/v1/request" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{
    "agent_id": "analyst",
    "intent": "Show me recent error logs and exception events from the auth service",
    "context": {"session_id": "demo-session-6", "purpose": "incident-response"}
  }' | python3 -m json.tool

# -----------------------------------------------------------------------
section "12. Data backends"
# -----------------------------------------------------------------------
info "InfluxDB UI:          http://localhost:8086"
info "  Username: admin / Password: admin12345"
info "  Explore the 'showcase' bucket with sample server metrics"
echo ""
info "MinIO Console:        http://localhost:9001"
info "  Username: minioadmin / Password: minioadmin"
info "  Browse the 'compliance-docs' bucket with tagged documents"
echo ""
info "Elasticsearch:        http://localhost:9200"
info "  curl http://localhost:9200/app-logs/_search?q=level:ERROR"
echo ""
info "Neo4j Browser:        http://localhost:7474"
info "  Username: neo4j / Password: nautilus2024"
info "  Try: MATCH (a:ThreatActor)-[r]->(t) RETURN a, r, t"

# -----------------------------------------------------------------------
section "13. Optional services"
# -----------------------------------------------------------------------
info "Locust load testing:  docker compose --profile bench up -d bench"
info "  UI: http://localhost:8089"
echo ""
info "SDK documentation:    docker compose --profile docs up -d docs"
info "  Site: http://localhost:8001"

echo ""
echo -e "${BOLD}${GREEN}Demo complete. All services are running.${NC}"
echo "Run 'docker compose logs -f nautilus' to see broker logs with trace IDs."
echo "Run 'docker compose down -v' to tear everything down."
