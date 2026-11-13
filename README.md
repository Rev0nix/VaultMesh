# VaultMesh — AWS Cloud Security Posture Management & Threat Detection Platform

[![VaultMesh DevSecOps Pipeline](https://github.com/Rev0nix/VaultMesh/actions/workflows/devsecops.yml/badge.svg)](https://github.com/Rev0nix/VaultMesh/actions/workflows/devsecops.yml)

> **Secure Your Cloud. Detect Threats. Control Everything.**

VaultMesh is a full-stack **Cloud Security Posture Management (CSPM)** and **CloudTrail Threat Detection** platform built with **FastAPI**, **React + TypeScript**, **SQLAlchemy**, and **Terraform**. It connects to AWS accounts via temporary **STS `AssumeRole` + `ExternalId`** credentials (or runs 100% offline in **Sandbox Mock Mode**) to discover cloud resources, detect misconfigurations, analyze IAM blast radius and VPC network exposure, detect suspicious CloudTrail activity, and export executive PDF/JSON security reports.

---

## Live Links

- **Live Web Console:** [https://vaultmesh-api-hxx0.onrender.com](https://vaultmesh-api-hxx0.onrender.com)
---

## Architecture Overview

```text
+-----------------------------------------------------------------------+
|                FRONTEND (React 18 • TypeScript • Tailwind)            |
|  Overview • Cloud Accounts • Findings • Threats • IAM • Network       |
|  Compliance • Audit Logs • PDF/JSON Reports • RBAC Settings           |
+-----------------------------------+-----------------------------------+
                                    | REST JSON (JWT Bearer Auth)
                                    v
+-----------------------------------------------------------------------+
|                    BACKEND API (Python 3.12 • FastAPI)                |
|  - RBAC Guard (ADMIN / SECURITY_ANALYST / VIEWER) & bcrypt Hashing    |
|  - Discovery Provider (Mock Sandbox OR Live boto3 STS AssumeRole)     |
|  - Multi-Service CSPM Scanner & Asymptotic Security Scoring Engine    |
|  - IAM Blast-Radius Analyzer & VPC Ingress Port Exposure Analyzer     |
|  - Explainable Rule-Based CloudTrail Threat Detection Engine          |
|  - Safe Remediation Engine (Dry-Run Default + Confirmation Gate)      |
+-----------------+-----------------------------------+-----------------+
                  | SQLAlchemy 2.0 ORM                | AWS STS / APIs
                  v                                   v
+---------------------------------+   +---------------------------------+
|   SQLite (Dev) / PostgreSQL     |   |   AWS Cloud / Sandbox Mock      |
|   13 Relational Security Tables |   |   S3 • IAM • EC2 • VPC • Trail  |
+---------------------------------+   +---------------------------------+