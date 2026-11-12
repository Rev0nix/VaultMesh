from typing import Any
from app.models.domain import CloudResource

HIGH_RISK_PORTS = {
    22: ("SSH", "CRITICAL", "Remote shell exposed to the internet; restrict to VPN/Bastion or use AWS SSM Session Manager."),
    3389: ("RDP", "CRITICAL", "Windows Remote Desktop exposed publicly; high ransomware target."),
    3306: ("MySQL", "CRITICAL", "Database port exposed publicly; restrict strictly to private application subnets."),
    5432: ("PostgreSQL", "CRITICAL", "Database port exposed publicly; remove 0.0.0.0/0 ingress immediately."),
    27017: ("MongoDB", "CRITICAL", "NoSQL database port exposed publicly; restrict to VPC internal security groups."),
    6379: ("Redis", "CRITICAL", "In-memory datastore port exposed publicly; restrict to internal VPC CIDR."),
}


class NetworkAnalyzerService:
    """Audits VPC Security Group ingress rules and classifies public port exposure."""

    @staticmethod
    def analyze_network_resources(resources: list[CloudResource]) -> dict[str, Any]:
        security_groups: list[dict[str, Any]] = []
        exposed_rules: list[dict[str, Any]] = []
        critical_port_exposures = 0
        public_ingress_count = 0

        for res in resources:
            if res.resource_type != "AWS::EC2::SecurityGroup":
                continue

            cfg = res.configuration or {}
            rules = cfg.get("ingress_rules", [])
            sg_exposed_count = 0

            for rule in rules:
                cidr = rule.get("cidr", "")
                from_p = int(rule.get("from_port", 0))
                to_p = int(rule.get("to_port", 65535))
                proto = str(rule.get("protocol", "tcp")).upper()
                is_public = cidr in ("0.0.0.0/0", "::/0")

                if is_public:
                    public_ingress_count += 1
                    sg_exposed_count += 1

                matched_risk = None
                for port, (svc_name, sev, advice) in HIGH_RISK_PORTS.items():
                    if is_public and from_p <= port <= to_p:
                        matched_risk = (svc_name, sev, advice)
                        critical_port_exposures += 1
                        break

                if matched_risk:
                    svc_name, sev, advice = matched_risk
                elif is_public and from_p in (80, 443):
                    svc_name = "HTTP" if from_p == 80 else "HTTPS"
                    sev = "INFO"
                    advice = "Standard public web ingress; ensure TLS/WAF protection is active."
                elif is_public:
                    svc_name = f"Port {from_p}-{to_p}"
                    sev = "HIGH"
                    advice = "Unrestricted 0.0.0.0/0 ingress on non-web port; narrow CIDR to trusted source IPs."
                else:
                    svc_name = f"Port {from_p}-{to_p}"
                    sev = "LOW"
                    advice = "Restricted CIDR source."

                exposed_rules.append({
                    "security_group_id": res.resource_id,
                    "security_group_name": res.resource_name or res.resource_id,
                    "region": res.region,
                    "vpc_id": cfg.get("vpc_id", "unknown"),
                    "protocol": proto,
                    "port_range": f"{from_p}" if from_p == to_p else f"{from_p}-{to_p}",
                    "service_label": svc_name,
                    "source_cidr": cidr,
                    "is_public": is_public,
                    "risk_level": sev,
                    "recommendation": advice,
                    "is_mock": res.is_mock,
                })

            security_groups.append({
                "id": res.id,
                "group_id": res.resource_id,
                "group_name": res.resource_name or res.resource_id,
                "arn": res.resource_arn,
                "region": res.region,
                "vpc_id": cfg.get("vpc_id", "unknown"),
                "total_ingress_rules": len(rules),
                "public_ingress_rules": sg_exposed_count,
                "is_mock": res.is_mock,
            })

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "LOW": 4}
        exposed_rules.sort(key=lambda r: severity_order.get(r["risk_level"], 5))

        return {
            "summary": {
                "total_security_groups": len(security_groups),
                "public_ingress_rules": public_ingress_count,
                "critical_admin_or_db_exposures": critical_port_exposures,
            },
            "security_groups": security_groups,
            "ingress_rules": exposed_rules,
        }
