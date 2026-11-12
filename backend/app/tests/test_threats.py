def test_cloudtrail_threat_detection_rules(client):
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "soc@vaultmesh.io",
            "full_name": "SOC Analyst",
            "password": "StrongPassword123!",
            "organization_name": "VaultMesh SOC Org",
        },
    )
    token = client.post(
        "/api/v1/auth/login",
        json={"email": "soc@vaultmesh.io", "password": "StrongPassword123!"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    acc = client.post(
        "/api/v1/accounts",
        headers=headers,
        json={
            "aws_account_id": "123456789012",
            "alias": "SOC Sandbox",
            "is_mock": True,
            "default_region": "ap-south-1",
            "regions": ["ap-south-1"],
        },
    ).json()

    run_res = client.post(
        "/api/v1/threats/analyze",
        headers=headers,
        json={"aws_account_id": acc["id"]},
    )
    assert run_res.status_code == 201
    assert run_res.json()["events_inspected"] == 8
    assert run_res.json()["alerts_matched"] == 5

    threats = client.get("/api/v1/threats", headers=headers).json()
    rules = {t["rule_triggered"] for t in threats}
    assert "AUTH_BRUTE_FORCE_SPIKE" in rules
    assert "CLOUDTRAIL_LOGGING_TAMPER" in rules
    assert "IAM_PRIVILEGE_ESCALATION" in rules
