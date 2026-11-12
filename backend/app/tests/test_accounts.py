def _get_admin_headers(client) -> dict[str, str]:
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "secops@vaultmesh.io",
            "full_name": "SecOps Lead",
            "password": "StrongPassword123!",
            "organization_name": "VaultMesh Cloud Org",
        },
    )
    res = client.post(
        "/api/v1/auth/login",
        json={"email": "secops@vaultmesh.io", "password": "StrongPassword123!"},
    )
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_connect_and_validate_mock_aws_account(client):
    headers = _get_admin_headers(client)

    tpl = client.get("/api/v1/accounts/onboarding-template", headers=headers)
    assert tpl.status_code == 200
    assert tpl.json()["generated_external_id"].startswith("vm-ext-")

    bad = client.post(
        "/api/v1/accounts",
        headers=headers,
        json={"aws_account_id": "12345", "alias": "Bad ID", "is_mock": True},
    )
    assert bad.status_code == 422

    created = client.post(
        "/api/v1/accounts",
        headers=headers,
        json={
            "aws_account_id": "123456789012",
            "alias": "AWS Security Sandbox (Mock)",
            "is_mock": True,
            "default_region": "ap-south-1",
            "regions": ["ap-south-1", "us-east-1"],
        },
    )
    assert created.status_code == 201
    account_db_id = created.json()["id"]
    assert created.json()["connection_status"] == "CONNECTED"

    val = client.post(f"/api/v1/accounts/{account_db_id}/validate", headers=headers)
    assert val.status_code == 200
    assert val.json()["status"] == "CONNECTED"
    assert "123456789012" in val.json()["caller_arn"]
