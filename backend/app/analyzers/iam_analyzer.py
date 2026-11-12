from typing import Any
from app.models.domain import CloudResource


class IAMAnalyzerService:
    """Analyzes IAM Users and Roles for wildcard privileges, MFA gaps, and trust risks."""

    @staticmethod
    def analyze_iam_resources(resources: list[CloudResource]) -> dict[str, Any]:
        principals: list[dict[str, Any]] = []
        wildcard_count = 0
        mfa_missing_count = 0
        risky_trust_count = 0

        for res in resources:
            if res.service != "IAM":
                continue

            cfg = res.configuration or {}
            attached = cfg.get("attached_policies", [])
            has_admin = (
                "arn:aws:iam::aws:policy/AdministratorAccess" in attached
                or bool(cfg.get("inline_wildcard_admin"))
            )
            mfa_enabled = cfg.get("mfa_enabled")
            console_access = bool(cfg.get("console_access"))
            trust_principal = cfg.get("trust_principal")
            risky_trust = bool(cfg.get("external_account_wildcard")) or trust_principal == "*"

            issues: list[str] = []
            recommendations: list[str] = []
            risk_score = 10

            if has_admin:
                wildcard_count += 1
                risk_score += 65
                issues.append("Unrestricted AdministratorAccess (*:*) attached")
                recommendations.append(
                    "Replace AdministratorAccess with granular service-scoped IAM policies restricted to required ARNs."
                )

            if res.resource_type == "AWS::IAM::User" and console_access and not mfa_enabled:
                mfa_missing_count += 1
                risk_score += 25
                issues.append("Console login enabled without MFA protection")
                recommendations.append(
                    "Enforce hardware or virtual MFA and apply a condition policy denying actions when aws:MultiFactorAuthPresent is false."
                )

            if risky_trust:
                risky_trust_count += 1
                risk_score += 50
                issues.append(f"Overly permissive trust relationship ({trust_principal})")
                recommendations.append(
                    "Restrict sts:AssumeRole trust policy Principal to explicit AWS account IDs with sts:ExternalId."
                )

            if not issues:
                recommendations.append("Principal follows least-privilege baseline. Continue periodic access reviews.")

            risk_score = min(100, risk_score)
            risk_level = (
                "CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 45 else "LOW"
            )

            principals.append({
                "id": res.id,
                "name": res.resource_name or res.resource_id,
                "arn": res.resource_arn,
                "principal_type": "IAM User" if res.resource_type == "AWS::IAM::User" else "IAM Role",
                "mfa_enabled": mfa_enabled,
                "trust_principal": trust_principal or "N/A (IAM User)",
                "attached_policies": attached,
                "has_wildcard_admin": has_admin,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "issues": issues,
                "recommendations": recommendations,
                "is_mock": res.is_mock,
            })

        principals.sort(key=lambda p: p["risk_score"], reverse=True)

        return {
            "summary": {
                "total_principals": len(principals),
                "wildcard_admin_principals": wildcard_count,
                "users_missing_mfa": mfa_missing_count,
                "risky_trust_policies": risky_trust_count,
            },
            "principals": principals,
        }
