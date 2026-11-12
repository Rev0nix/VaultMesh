def test_full_scan_and_findings_lifecycle(client):
    # 1. Register Admin & login
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "cspm@vaultmesh.io",
            "full_name": "CSPM Architect",
            "password": "StrongPassword123!",
            "organization_name": "VaultMesh Scan Org",
        },
    )
    token = client.post(
        "/api/v1/auth/login",
        json={"email": "cspm@vaultmesh.io", "password": "StrongPassword123!"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Connect Sandbox Mock AWS Account
    acc = client.post(
        "/api/v1/accounts",
        headers=headers,
        json={
            "aws_account_id": "123456789012",
            "alias": "Sandbox Mock",
            "is_mock": True,
            "default_region": "ap-south-1",
            "regions": ["ap-south-1"],
        },
    ).json()

    # 3. Trigger Security Scan
    scan_res = client.post(
        "/api/v1/scans/run",
        headers=headers,
        json={"aws_account_id": acc["id"]},
    )
    assert scan_res.status_code == 201
    scan_data = scan_res.json()
    assert scan_data["status"] == "COMPLETED"
    assert scan_data["resources_scanned"] == 8
    assert scan_data["findings_count"] == 9
    assert scan_data["security_score"] < 100

    # 4. List Findings & Resolve a Critical finding -> verify score improves
    findings = client.get("/api/v1/findings", headers=headers).json()
    assert len(findings) == 9
    critical_finding = next(f for f in findings if f["severity"] == "CRITICAL")

    patch_res = client.patch(
        f"/api/v1/findings/{critical_finding['id']}",
        headers=headers,
        json={
            "status": "RESOLVED",
            "investigation_notes": "Enabled S3 Block Public Access via Terraform.",
        },
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "RESOLVED"

    overview = client.get("/api/v1/dashboard/overview", headers=headers).json()
    assert overview["security_score"] > scan_data["security_score"]
