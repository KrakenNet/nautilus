"""Seed all backends with sample data for the Nautilus showcase.

Run inside the `seed` docker-compose service after all backends are healthy.
Seeds: InfluxDB, MinIO, Elasticsearch, Neo4j.
(Postgres is seeded via init.sql in docker-entrypoint-initdb.d.)
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Wait for services
# ---------------------------------------------------------------------------


def _wait_http(url: str, label: str, retries: int = 30, delay: float = 2.0) -> None:
    """Block until ``url`` returns a 2xx response."""
    import urllib.request
    import urllib.error

    for attempt in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if 200 <= resp.status < 300:
                    print(f"  {label} ready ({resp.status})")
                    return
        except Exception:
            pass
        print(f"  waiting for {label}... ({attempt + 1}/{retries})")
        time.sleep(delay)
    raise RuntimeError(f"{label} not reachable at {url} after {retries} attempts")


# ---------------------------------------------------------------------------
# InfluxDB seeding
# ---------------------------------------------------------------------------


def seed_influxdb() -> None:
    """Write sample time-series data points into the 'showcase' bucket."""
    from influxdb_client import InfluxDBClient, Point, WritePrecision
    from influxdb_client.client.write_api import SYNCHRONOUS

    url = os.environ["INFLUXDB_URL"]
    token = os.environ["INFLUXDB_TOKEN"]
    org = os.environ["INFLUXDB_ORG"]
    bucket = os.environ["INFLUXDB_BUCKET"]

    client = InfluxDBClient(url=url, token=token, org=org)
    write_api = client.write_api(write_options=SYNCHRONOUS)

    now = datetime.now(timezone.utc)
    hosts = ["web-01", "web-02", "db-01", "worker-01"]
    points = []

    for i in range(96):  # 24 hours of data at 15-min intervals
        ts = now - timedelta(minutes=15 * (96 - i))
        for host in hosts:
            # CPU usage (0-100%)
            import random

            cpu = 20 + random.random() * 60 + (10 if host == "db-01" else 0)
            mem = 40 + random.random() * 40 + (15 if host == "db-01" else 0)
            disk_read = random.random() * 500
            net_rx = random.random() * 1000

            points.append(
                Point("system")
                .tag("host", host)
                .tag("region", "us-east-1")
                .field("cpu_percent", round(min(cpu, 99.5), 1))
                .field("memory_percent", round(min(mem, 98.0), 1))
                .field("disk_read_mbps", round(disk_read, 2))
                .field("network_rx_mbps", round(net_rx, 2))
                .time(ts, WritePrecision.S)
            )

    write_api.write(bucket=bucket, org=org, record=points)
    client.close()
    print(f"  InfluxDB: wrote {len(points)} data points to bucket '{bucket}'")


# ---------------------------------------------------------------------------
# MinIO seeding
# ---------------------------------------------------------------------------


def seed_minio() -> None:
    """Create a bucket and upload sample compliance documents to MinIO."""
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import ClientError

    endpoint = os.environ["MINIO_ENDPOINT"]
    access_key = os.environ["MINIO_ACCESS_KEY"]
    secret_key = os.environ["MINIO_SECRET_KEY"]
    bucket = "compliance-docs"

    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-east-1",
        config=BotoConfig(signature_version="s3v4"),
    )

    # Create bucket (idempotent)
    try:
        s3.create_bucket(Bucket=bucket)
        print(f"  MinIO: created bucket '{bucket}'")
    except ClientError as e:
        if e.response["Error"]["Code"] != "BucketAlreadyOwnedByYou":
            raise
        print(f"  MinIO: bucket '{bucket}' already exists")

    # Sample documents
    documents = {
        "reports/q1-2024-security-audit.json": {
            "title": "Q1 2024 Security Audit Report",
            "date": "2024-03-31",
            "framework": "NIST SP 800-53",
            "status": "compliant",
            "findings": 3,
            "critical_findings": 0,
            "summary": "All AC and SC controls evaluated. Minor gaps in AC-6 least privilege for service accounts.",
        },
        "reports/q2-2024-hipaa-assessment.json": {
            "title": "Q2 2024 HIPAA Risk Assessment",
            "date": "2024-06-30",
            "framework": "HIPAA",
            "status": "compliant_with_observations",
            "findings": 5,
            "critical_findings": 1,
            "summary": "PHI access controls meet minimum necessary standard. Breach notification procedures need update.",
        },
        "policies/data-classification-policy.json": {
            "title": "Data Classification Policy v3.2",
            "effective_date": "2024-01-01",
            "levels": ["unclassified", "cui-basic", "cui-specified"],
            "review_cycle": "annual",
            "owner": "Chief Information Security Officer",
        },
        "policies/incident-response-plan.json": {
            "title": "Incident Response Plan v2.1",
            "effective_date": "2024-02-15",
            "phases": ["preparation", "detection", "containment", "eradication", "recovery", "lessons-learned"],
            "sla_critical_hours": 4,
            "sla_high_hours": 24,
        },
        "audit-trails/2024-access-review.json": {
            "title": "2024 Annual Access Review",
            "date": "2024-04-15",
            "accounts_reviewed": 342,
            "accounts_revoked": 17,
            "accounts_modified": 45,
            "compliance_rate": 0.95,
        },
    }

    tags_map = {
        "reports/q1-2024-security-audit.json": {"framework": "nist", "classification": "cui-specified", "type": "report"},
        "reports/q2-2024-hipaa-assessment.json": {"framework": "hipaa", "classification": "cui-specified", "type": "report"},
        "policies/data-classification-policy.json": {"type": "policy", "classification": "cui-basic"},
        "policies/incident-response-plan.json": {"type": "policy", "classification": "cui-basic"},
        "audit-trails/2024-access-review.json": {"type": "audit-trail", "classification": "cui-specified"},
    }

    for key, content in documents.items():
        body = json.dumps(content, indent=2).encode("utf-8")
        s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/json")

        tags = tags_map.get(key, {})
        if tags:
            tag_set = [{"Key": k, "Value": v} for k, v in tags.items()]
            s3.put_object_tagging(
                Bucket=bucket,
                Key=key,
                Tagging={"TagSet": tag_set},
            )

    print(f"  MinIO: uploaded {len(documents)} documents to '{bucket}'")


# ---------------------------------------------------------------------------
# Elasticsearch seeding
# ---------------------------------------------------------------------------


def seed_elasticsearch() -> None:
    """Index sample application log events into Elasticsearch."""
    from elasticsearch import Elasticsearch

    es_url = os.environ["ES_URL"]
    es = Elasticsearch(es_url)

    logs = [
        {"timestamp": "2024-08-15T10:23:45Z", "level": "ERROR", "service": "auth-service", "message": "JWT validation failed: token expired", "trace_id": "abc123", "user_id": "u-4421"},
        {"timestamp": "2024-08-15T10:24:01Z", "level": "WARN", "service": "api-gateway", "message": "Rate limit approaching for client app-mobile (450/500 rpm)", "trace_id": "def456", "client": "app-mobile"},
        {"timestamp": "2024-08-15T10:25:12Z", "level": "ERROR", "service": "storage-svc", "message": "S3 upload failed: connection timeout after 30s", "trace_id": "ghi789", "bucket": "user-uploads"},
        {"timestamp": "2024-08-15T10:26:30Z", "level": "INFO", "service": "auth-service", "message": "Successful login from new device", "trace_id": "jkl012", "user_id": "u-1187", "ip": "203.0.113.42"},
        {"timestamp": "2024-08-15T10:27:45Z", "level": "ERROR", "service": "policy-engine", "message": "Rule evaluation timeout: RBAC policy exceeded 500ms SLA", "trace_id": "mno345", "rule": "rbac-v2"},
        {"timestamp": "2024-08-15T10:28:15Z", "level": "WARN", "service": "event-bus", "message": "Consumer lag exceeding threshold: 15000 messages behind", "trace_id": "pqr678", "topic": "audit-events"},
        {"timestamp": "2024-08-15T10:30:00Z", "level": "ERROR", "service": "api-gateway", "message": "Upstream service unavailable: circuit breaker OPEN for payment-svc", "trace_id": "stu901", "upstream": "payment-svc"},
        {"timestamp": "2024-08-15T10:31:22Z", "level": "INFO", "service": "monitoring", "message": "Health check recovered: db-01 PostgreSQL connection pool restored", "trace_id": "vwx234", "host": "db-01"},
    ]

    index_name = "app-logs"
    for i, doc in enumerate(logs):
        es.index(index=index_name, id=str(i + 1), document=doc)

    es.indices.refresh(index=index_name)
    print(f"  Elasticsearch: indexed {len(logs)} log events in '{index_name}'")


# ---------------------------------------------------------------------------
# Neo4j seeding
# ---------------------------------------------------------------------------


def seed_neo4j() -> None:
    """Create a small threat intelligence knowledge graph in Neo4j."""
    from neo4j import GraphDatabase

    url = os.environ["NEO4J_URL"]
    user = os.environ["NEO4J_USER"]
    password = os.environ["NEO4J_PASS"]

    driver = GraphDatabase.driver(url, auth=(user, password))

    with driver.session() as session:
        # Create threat actors
        session.run(
            "MERGE (a:ThreatActor {name: 'APT-29', aliases: 'Cozy Bear', origin: 'Russia', active_since: '2008'})"
        )
        session.run(
            "MERGE (a:ThreatActor {name: 'APT-41', aliases: 'Winnti', origin: 'China', active_since: '2012'})"
        )

        # Create TTPs (MITRE ATT&CK)
        session.run(
            "MERGE (t:Technique {id: 'T1566', name: 'Phishing', tactic: 'Initial Access'})"
        )
        session.run(
            "MERGE (t:Technique {id: 'T1078', name: 'Valid Accounts', tactic: 'Persistence'})"
        )
        session.run(
            "MERGE (t:Technique {id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access'})"
        )

        # Create IOCs
        session.run(
            "MERGE (i:Indicator {type: 'domain', value: 'malicious-updates.example.com', confidence: 'high'})"
        )
        session.run(
            "MERGE (i:Indicator {type: 'ip', value: '198.51.100.23', confidence: 'medium'})"
        )

        # Create campaigns
        session.run(
            "MERGE (c:Campaign {name: 'SolarWinds Compromise', year: 2020, sector: 'Government'})"
        )

        # Relationships
        session.run("""
            MATCH (a:ThreatActor {name: 'APT-29'}), (t:Technique {id: 'T1566'})
            MERGE (a)-[:USES]->(t)
        """)
        session.run("""
            MATCH (a:ThreatActor {name: 'APT-29'}), (t:Technique {id: 'T1078'})
            MERGE (a)-[:USES]->(t)
        """)
        session.run("""
            MATCH (a:ThreatActor {name: 'APT-41'}), (t:Technique {id: 'T1190'})
            MERGE (a)-[:USES]->(t)
        """)
        session.run("""
            MATCH (a:ThreatActor {name: 'APT-29'}), (c:Campaign {name: 'SolarWinds Compromise'})
            MERGE (a)-[:ATTRIBUTED_TO]->(c)
        """)
        session.run("""
            MATCH (c:Campaign {name: 'SolarWinds Compromise'}), (i:Indicator {value: 'malicious-updates.example.com'})
            MERGE (c)-[:INDICATES]->(i)
        """)

    driver.close()
    print("  Neo4j: created threat intelligence graph (2 actors, 3 TTPs, 2 IOCs, 1 campaign)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Nautilus showcase: seeding data...")

    print("\nWaiting for services:")
    _wait_http(os.environ["INFLUXDB_URL"] + "/health", "InfluxDB")
    _wait_http(os.environ["MINIO_ENDPOINT"] + "/minio/health/live", "MinIO")
    _wait_http(os.environ["ES_URL"] + "/_cluster/health", "Elasticsearch")

    print("\nSeeding InfluxDB:")
    seed_influxdb()

    print("\nSeeding MinIO:")
    seed_minio()

    print("\nSeeding Elasticsearch:")
    seed_elasticsearch()

    print("\nSeeding Neo4j:")
    seed_neo4j()

    print("\nDone. All sample data is loaded.")
