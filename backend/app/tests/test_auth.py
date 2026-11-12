import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.api.deps import get_db
from app.core.database import Base
from app.main import app

SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./test_vaultmesh.db"
engine = create_engine(SQLALCHEMY_TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def setup_and_teardown_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


client = TestClient(app)


def test_register_login_and_rbac_flow():
    # 1. First user in a new org receives ADMIN role automatically
    res_admin = client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@vaultmesh.io",
            "full_name": "Revanth Admin",
            "password": "StrongPassword123!",
            "organization_name": "VaultMesh Lab",
        },
    )
    assert res_admin.status_code == 201
    assert res_admin.json()["role"] == "ADMIN"

    # 2. Second user joining the same org receives SECURITY_ANALYST role
    res_analyst = client.post(
        "/api/v1/auth/register",
        json={
            "email": "analyst@vaultmesh.io",
            "full_name": "Cloud Analyst",
            "password": "StrongPassword123!",
            "organization_name": "VaultMesh Lab",
        },
    )
    assert res_analyst.status_code == 201
    assert res_analyst.json()["role"] == "SECURITY_ANALYST"

    # 3. Login as Analyst and verify JWT token works on /me
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@vaultmesh.io", "password": "StrongPassword123!"},
    )
    assert login_res.status_code == 200
    analyst_token = login_res.json()["access_token"]

    me_res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "analyst@vaultmesh.io"

    # 4. RBAC Enforcement: Analyst MUST be blocked (403) from ADMIN-only endpoint
    forbidden_res = client.get(
        "/api/v1/auth/admin-check",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert forbidden_res.status_code == 403

    # 5. Login as Admin and verify ADMIN-only endpoint succeeds (200)
    admin_login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@vaultmesh.io", "password": "StrongPassword123!"},
    )
    admin_token = admin_login.json()["access_token"]
    ok_res = client.get(
        "/api/v1/auth/admin-check",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert ok_res.status_code == 200
    assert ok_res.json()["role"] == "ADMIN"
