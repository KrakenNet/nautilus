"""Fire sample broker queries to populate the audit log and decisions page.

Run after Nautilus is healthy. Each query exercises a different source adapter
and clearance level so the admin UI has real data to show.

Agent IDs must match nautilus.yaml: analyst, auditor, intern.
Purposes must match source allowed_purposes.
"""

import json
import sys
import time
import urllib.request
import urllib.error

NAUTILUS_URL = "http://nautilus:8000"
API_KEY = "demo-key-2024"

QUERIES = [
    # analyst (cui-basic) → vuln_db via threat-analysis
    {
        "agent_id": "analyst",
        "intent": "Show critical CVEs from the last 30 days affecting Linux servers",
        "context": {"purpose": "threat-analysis"},
    },
    # intern (unclassified) → server_metrics via monitoring
    {
        "agent_id": "intern",
        "intent": "What is the CPU utilization trend for production servers?",
        "context": {"purpose": "monitoring"},
    },
    # auditor (cui-specified) → compliance_docs via compliance-audit
    {
        "agent_id": "auditor",
        "intent": "Retrieve the latest FedRAMP compliance assessment report",
        "context": {"purpose": "compliance-audit"},
    },
    # analyst (cui-basic) → app_logs via incident-response
    {
        "agent_id": "analyst",
        "intent": "Find ERROR level log entries from the authentication service",
        "context": {"purpose": "incident-response"},
    },
    # analyst (cui-basic) → threat_graph via threat-analysis
    {
        "agent_id": "analyst",
        "intent": "Find threat actors linked to ransomware campaigns",
        "context": {"purpose": "threat-analysis"},
    },
    # intern (unclassified) requesting cui-specified data → expect denial
    {
        "agent_id": "intern",
        "intent": "Get the FedRAMP audit trail and compliance reports",
        "context": {"purpose": "compliance-audit"},
    },
    # analyst (cui-basic) → threat_graph via incident-response
    {
        "agent_id": "analyst",
        "intent": "Correlate network IOCs with known threat actor infrastructure",
        "context": {"purpose": "incident-response"},
    },
    # intern (unclassified) → server_metrics via monitoring
    {
        "agent_id": "intern",
        "intent": "Show server memory and disk metrics for the last hour",
        "context": {"purpose": "monitoring"},
    },
]


def wait_for_ready(url: str, max_wait: int = 120) -> bool:
    """Poll /readyz until Nautilus is ready."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            req = urllib.request.Request(f"{url}/readyz")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def send_query(url: str, query: dict) -> dict | None:
    """POST a broker request and return the response."""
    body = json.dumps(query).encode()
    req = urllib.request.Request(
        f"{url}/v1/request",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            queried = data.get("sources_queried", [])
            denied = data.get("sources_denied", [])
            print(f"    queried={queried}  denied={denied}")
            return data
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"    HTTP {e.code}: {body[:200]}")
        return None
    except Exception as e:
        print(f"    Error: {e}")
        return None


def main() -> None:
    print("demo-queries: waiting for Nautilus to be ready...")
    if not wait_for_ready(NAUTILUS_URL):
        print("demo-queries: Nautilus not ready after 120s, giving up")
        sys.exit(1)

    print(f"demo-queries: Nautilus ready, firing {len(QUERIES)} sample queries")
    success = 0
    for i, q in enumerate(QUERIES, 1):
        print(f"  [{i}/{len(QUERIES)}] agent={q['agent_id']}: {q['intent'][:60]}...")
        result = send_query(NAUTILUS_URL, q)
        if result is not None:
            success += 1
        time.sleep(0.5)

    print(f"demo-queries: done — {success}/{len(QUERIES)} succeeded")


if __name__ == "__main__":
    main()
