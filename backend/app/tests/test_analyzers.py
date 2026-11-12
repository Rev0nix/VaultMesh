def test_iam_and_network_analyzers(client):
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "analyzer@vaultmesh.io",
            "full_name": "IAM Net Lead",
            "password": "StrongPassword123!",
            "organization_name": "VaultMesh Analyzer Org",
        },
    )
    token = client.post(
        "/api/v1/auth/login",
        json={"email": "analyzer@vaultmesh.io", "password": "StrongPassword123!"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    acc = client.post(
        "/api/v1/accounts",
        headers=headers,
        json={
            "aws_account_id": "123456789012",
            "alias": "Analyzer Sandbox",
            "is_mock": True,
            "default_region": "ap-south-1",
            "regions": ["ap-south-1"],
        },
    ).json()

    client.post("/api/v1/scans/run", headers=headers, json={"aws_account_id": acc["id"]})

    iam_res = client.get("/api/v1/analyzers/iam", headers=headers)
    assert iam_res.status_code == 200
    iam_data = iam_res.json()
    assert iam_data["summary"]["total_principals"] == 2
    assert iam_data["summary"]["wildcard_admin_principals"] == 1
    assert iam_data["summary"]["users_missing_mfa"] == 1

    net_res = client.get("/api/v1/analyzers/network", headers=headers)
    assert net_res.status_code == 200
    net_data = net_res.json()
    assert net_data["summary"]["total_security_groups"] == 1
    assert net_data["summary"]["critical_admin_or_db_exposures"] == 2
