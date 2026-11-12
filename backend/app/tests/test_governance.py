def test_remediation_compliance_audit_and_reports(client):
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "gov@vaultmesh.io",
            "full_name": "Governance Lead",
            "password": "StrongPassword123!",
            "organization_name": "VaultMesh Governance Org",
        },
    )
    token = client.post(
        "/api/v1/auth/login",
        json={"email": "gov@vaultmesh.io", "password": "StrongPassword123!"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    acc = client.post(
        "/api/v1/accounts",
        headers=headers,
        json={
            "aws_account_id": "123456789012",
            "alias": "Gov Sandbox",
            "is_mock": True,
            "default_region": "ap-south-1",
            "regions": ["ap-south-1"],
        },
    ).json()
    client.post("/api/v1/scans/run", headers=headers, json={"aws_account_id": acc["id"]})

    findings = client.get("/api/v1/findings", headers=headers).json()
    target = findings[0]

    # 1. Dry-run remediation succeeds without resolving finding
    dry = client.post(
        "/api/v1/remediation/execute",
        headers=headers,
        json={"finding_id": target["id"], "dry_run": True, "confirm": False},
    )
    assert dry.status_code == 200
    assert dry.json()["status"] == "SIMULATED"
    assert dry.json()["finding_status"] == "OPEN"

    # 2. Live remediation without confirm=True MUST be rejected (400)
    unconfirmed = client.post(
        "/api/v1/remediation/execute",
        headers=headers,
        json={"finding_id": target["id"], "dry_run": False, "confirm": False},
    )
    assert unconfirmed.status_code == 400

    # 3. Confirmed remediation succeeds and resolves finding
    confirmed = client.post(
        "/api/v1/remediation/execute",
        headers=headers,
        json={"finding_id": target["id"], "dry_run": False, "confirm": True},
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["finding_status"] == "RESOLVED"

    # 4. Compliance & Audit Logs
    comp = client.get("/api/v1/compliance", headers=headers).json()
    assert comp["summary"]["total_controls"] == 9

    logs = client.get("/api/v1/audit/logs", headers=headers).json()
    assert len(logs) >= 4

    # 5. JSON & PDF report exports
    json_rep = client.get("/api/v1/reports/export?fmt=json", headers=headers)
    assert json_rep.status_code == 200
    assert "executive_summary" in json_rep.json()

    pdf_rep = client.get("/api/v1/reports/export?fmt=pdf", headers=headers)
    assert pdf_rep.status_code == 200
    assert pdf_rep.content.startswith(b"%PDF")
