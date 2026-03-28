"""
Cloud Security Posture Management (CSPM) Module
================================================
Covers: AWS IAM, S3, EC2, RDS, CloudTrail checks
Requirements: boto3, rich, pyyaml
    pip install boto3 rich pyyaml
"""

import boto3
import json
import yaml
import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


# ──────────────────────────────────────────────
# 1. ENUMS & DATA MODELS
# ──────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"

SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "white",
}

@dataclass
class Finding:
    rule_id:      str
    title:        str
    severity:     Severity
    status:       Status
    resource_id:  str
    resource_type: str
    region:       str
    description:  str
    remediation:  str
    timestamp:    str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    details:      dict = field(default_factory=dict)


# ──────────────────────────────────────────────
# 2. BASE CONNECTOR
# ──────────────────────────────────────────────

class AWSConnector:
    """Thin wrapper around boto3 that caches clients."""

    def __init__(self, profile: Optional[str] = None, region: str = "us-east-1"):
        self.region  = region
        session_kwargs = {"region_name": region}
        if profile:
            session_kwargs["profile_name"] = profile
        self.session = boto3.Session(**session_kwargs)
        self._clients: dict = {}

    def client(self, service: str):
        if service not in self._clients:
            self._clients[service] = self.session.client(service)
        return self._clients[service]

    def get_account_id(self) -> str:
        return self.client("sts").get_caller_identity()["Account"]


# ──────────────────────────────────────────────
# 3. BASE CHECK CLASS
# ──────────────────────────────────────────────

class BaseCheck:
    """All security checks inherit from this."""
    rule_id:      str = ""
    title:        str = ""
    severity:     Severity = Severity.MEDIUM
    resource_type: str = ""

    def __init__(self, connector: AWSConnector):
        self.conn = connector

    def run(self) -> list[Finding]:
        raise NotImplementedError

    def _finding(self, status, resource_id, description, remediation, details=None) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            status=status,
            resource_id=resource_id,
            resource_type=self.resource_type,
            region=self.conn.region,
            description=description,
            remediation=remediation,
            details=details or {},
        )


# ──────────────────────────────────────────────
# 4. SECURITY CHECKS
# ──────────────────────────────────────────────

# ── IAM ──────────────────────────────────────

class CheckIAMRootMFA(BaseCheck):
    rule_id       = "IAM_001"
    title         = "Root account MFA not enabled"
    severity      = Severity.CRITICAL
    resource_type = "aws_iam_account"

    def run(self):
        findings = []
        try:
            summary = self.conn.client("iam").get_account_summary()["SummaryMap"]
            mfa_enabled = summary.get("AccountMFAEnabled", 0)
            status = Status.PASS if mfa_enabled else Status.FAIL
            findings.append(self._finding(
                status=status,
                resource_id="root",
                description="Root account MFA is enabled." if mfa_enabled else "Root account MFA is NOT enabled.",
                remediation="Enable MFA on the root account via IAM console → Security credentials.",
                details={"mfa_enabled": bool(mfa_enabled)},
            ))
        except Exception as e:
            findings.append(self._finding(Status.ERROR, "root", str(e), ""))
        return findings


class CheckIAMUnusedCredentials(BaseCheck):
    rule_id       = "IAM_002"
    title         = "IAM users with unused credentials (>90 days)"
    severity      = Severity.HIGH
    resource_type = "aws_iam_user"

    def run(self):
        findings = []
        iam = self.conn.client("iam")
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    uname = user["UserName"]
                    keys = iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]
                    for key in keys:
                        if key["Status"] != "Active":
                            continue
                        last = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                        lu = last["AccessKeyLastUsed"].get("LastUsedDate")
                        if lu:
                            days = (datetime.datetime.now(datetime.timezone.utc) - lu).days
                            if days > 90:
                                findings.append(self._finding(
                                    status=Status.FAIL,
                                    resource_id=uname,
                                    description=f"Access key {key['AccessKeyId']} unused for {days} days.",
                                    remediation="Disable or delete unused IAM access keys older than 90 days.",
                                    details={"key_id": key["AccessKeyId"], "days_unused": days},
                                ))
                            else:
                                findings.append(self._finding(Status.PASS, uname,
                                    f"Key used {days} days ago.", "", {"days_unused": days}))
        except Exception as e:
            findings.append(self._finding(Status.ERROR, "iam_users", str(e), ""))
        return findings


class CheckIAMAdminPolicies(BaseCheck):
    rule_id       = "IAM_003"
    title         = "IAM users with direct AdministratorAccess policy"
    severity      = Severity.HIGH
    resource_type = "aws_iam_user"

    def run(self):
        findings = []
        iam = self.conn.client("iam")
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    uname = user["UserName"]
                    attached = iam.list_attached_user_policies(UserName=uname)["AttachedPolicies"]
                    admin = [p for p in attached if p["PolicyName"] == "AdministratorAccess"]
                    if admin:
                        findings.append(self._finding(
                            status=Status.FAIL,
                            resource_id=uname,
                            description=f"User '{uname}' has AdministratorAccess directly attached.",
                            remediation="Use IAM groups/roles for admin access instead of direct user policies.",
                            details={"policies": [p["PolicyName"] for p in admin]},
                        ))
                    else:
                        findings.append(self._finding(Status.PASS, uname,
                            "No direct AdministratorAccess policy.", ""))
        except Exception as e:
            findings.append(self._finding(Status.ERROR, "iam_users", str(e), ""))
        return findings


# ── S3 ───────────────────────────────────────

class CheckS3PublicAccess(BaseCheck):
    rule_id       = "S3_001"
    title         = "S3 bucket with public access enabled"
    severity      = Severity.CRITICAL
    resource_type = "aws_s3_bucket"

    def run(self):
        findings = []
        s3 = self.conn.client("s3")
        try:
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                    blocked = all([
                        cfg.get("BlockPublicAcls", False),
                        cfg.get("IgnorePublicAcls", False),
                        cfg.get("BlockPublicPolicy", False),
                        cfg.get("RestrictPublicBuckets", False),
                    ])
                    status = Status.PASS if blocked else Status.FAIL
                    findings.append(self._finding(
                        status=status,
                        resource_id=name,
                        description="All public access blocks enabled." if blocked else f"Bucket '{name}' is NOT fully blocking public access.",
                        remediation="Enable all 4 Block Public Access settings on the S3 bucket.",
                        details=cfg,
                    ))
                except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                    findings.append(self._finding(
                        status=Status.FAIL,
                        resource_id=name,
                        description=f"Bucket '{name}' has NO public access block configuration.",
                        remediation="Enable S3 Block Public Access on the bucket.",
                    ))
        except Exception as e:
            findings.append(self._finding(Status.ERROR, "s3", str(e), ""))
        return findings


class CheckS3Encryption(BaseCheck):
    rule_id       = "S3_002"
    title         = "S3 bucket without default encryption"
    severity      = Severity.MEDIUM
    resource_type = "aws_s3_bucket"

    def run(self):
        findings = []
        s3 = self.conn.client("s3")
        try:
            for bucket in s3.list_buckets().get("Buckets", []):
                name = bucket["Name"]
                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                    rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
                    algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                    findings.append(self._finding(Status.PASS, name,
                        f"Bucket encrypted with {algo}.", "", {"algorithm": algo}))
                except s3.exceptions.ClientError as e:
                    if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                        findings.append(self._finding(
                            status=Status.FAIL,
                            resource_id=name,
                            description=f"Bucket '{name}' has no default encryption.",
                            remediation="Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
                        ))
        except Exception as e:
            findings.append(self._finding(Status.ERROR, "s3", str(e), ""))
        return findings


# ── EC2 ──────────────────────────────────────

class CheckEC2OpenSSH(BaseCheck):
    rule_id       = "EC2_001"
    title         = "Security group allows SSH (22) open to the world"
    severity      = Severity.CRITICAL
    resource_type = "aws_security_group"

    def run(self):
        findings = []
        ec2 = self.conn.client("ec2")
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    exposed = False
                    for rule in sg.get("IpPermissions", []):
                        if rule.get("FromPort") == 22 or rule.get("IpProtocol") == "-1":
                            for cidr in rule.get("IpRanges", []):
                                if cidr.get("CidrIp") == "0.0.0.0/0":
                                    exposed = True
                            for cidr6 in rule.get("Ipv6Ranges", []):
                                if cidr6.get("CidrIpv6") == "::/0":
                                    exposed = True
                    if exposed:
                        findings.append(self._finding(
                            status=Status.FAIL,
                            resource_id=sg_id,
                            description=f"SG '{sg_id}' ({sg.get('GroupName')}) allows SSH from 0.0.0.0/0.",
                            remediation="Restrict SSH to known IP ranges or use AWS Systems Manager Session Manager.",
                            details={"group_name": sg.get("GroupName")},
                        ))
                    else:
                        findings.append(self._finding(Status.PASS, sg_id,
                            "SSH not open to the world.", ""))
        except Exception as e:
            findings.append(self._finding(Status.ERROR, "ec2_sg", str(e), ""))
        return findings


class CheckEC2EBSEncryption(BaseCheck):
    rule_id       = "EC2_002"
    title         = "EBS volumes not encrypted"
    severity      = Severity.HIGH
    resource_type = "aws_ebs_volume"

    def run(self):
        findings = []
        ec2 = self.conn.client("ec2")
        try:
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page["Volumes"]:
                    vid = vol["VolumeId"]
                    if not vol.get("Encrypted", False):
                        findings.append(self._finding(
                            status=Status.FAIL,
                            resource_id=vid,
                            description=f"EBS volume '{vid}' is NOT encrypted.",
                            remediation="Enable EBS encryption by default or re-create volumes with encryption.",
                            details={"size_gb": vol.get("Size"), "state": vol.get("State")},
                        ))
                    else:
                        findings.append(self._finding(Status.PASS, vid,
                            "Volume is encrypted.", ""))
        except Exception as e:
            findings.append(self._finding(Status.ERROR, "ebs", str(e), ""))
        return findings


# ── RDS ──────────────────────────────────────

class CheckRDSPubliclyAccessible(BaseCheck):
    rule_id       = "RDS_001"
    title         = "RDS instance publicly accessible"
    severity      = Severity.CRITICAL
    resource_type = "aws_rds_instance"

    def run(self):
        findings = []
        rds = self.conn.client("rds")
        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    db_id = db["DBInstanceIdentifier"]
                    if db.get("PubliclyAccessible"):
                        findings.append(self._finding(
                            status=Status.FAIL,
                            resource_id=db_id,
                            description=f"RDS instance '{db_id}' is publicly accessible.",
                            remediation="Set PubliclyAccessible=false and place the RDS instance in a private subnet.",
                            details={"engine": db.get("Engine"), "endpoint": db.get("Endpoint", {}).get("Address")},
                        ))
                    else:
                        findings.append(self._finding(Status.PASS, db_id,
                            "RDS instance is not publicly accessible.", ""))
        except Exception as e:
            findings.append(self._finding(Status.ERROR, "rds", str(e), ""))
        return findings


# ── CloudTrail ────────────────────────────────

class CheckCloudTrailEnabled(BaseCheck):
    rule_id       = "CT_001"
    title         = "CloudTrail not enabled in all regions"
    severity      = Severity.HIGH
    resource_type = "aws_cloudtrail"

    def run(self):
        findings = []
        ct = self.conn.client("cloudtrail")
        try:
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
            if not trails:
                findings.append(self._finding(
                    status=Status.FAIL,
                    resource_id="cloudtrail",
                    description="No CloudTrail trails found in this region.",
                    remediation="Enable CloudTrail with multi-region logging and log file validation.",
                ))
            else:
                for trail in trails:
                    name = trail["Name"]
                    status_info = ct.get_trail_status(Name=trail["TrailARN"])
                    is_logging = status_info.get("IsLogging", False)
                    multi = trail.get("IsMultiRegionTrail", False)
                    validated = trail.get("LogFileValidationEnabled", False)
                    ok = is_logging and multi and validated
                    findings.append(self._finding(
                        status=Status.PASS if ok else Status.FAIL,
                        resource_id=name,
                        description=f"Trail '{name}': logging={is_logging}, multi_region={multi}, validation={validated}",
                        remediation="Ensure trail has IsLogging=true, IsMultiRegionTrail=true, LogFileValidationEnabled=true.",
                        details={"is_logging": is_logging, "multi_region": multi, "log_validation": validated},
                    ))
        except Exception as e:
            findings.append(self._finding(Status.ERROR, "cloudtrail", str(e), ""))
        return findings


# ──────────────────────────────────────────────
# 5. SCANNER ENGINE
# ──────────────────────────────────────────────

class CSPMScanner:
    """Orchestrates all checks and collects findings."""

    CHECKS = [
        CheckIAMRootMFA,
        CheckIAMUnusedCredentials,
        CheckIAMAdminPolicies,
        CheckS3PublicAccess,
        CheckS3Encryption,
        CheckEC2OpenSSH,
        CheckEC2EBSEncryption,
        CheckRDSPubliclyAccessible,
        CheckCloudTrailEnabled,
    ]

    def __init__(self, connector: AWSConnector):
        self.connector = connector
        self.findings:  list[Finding] = []

    def run(self, check_ids: Optional[list[str]] = None) -> list[Finding]:
        self.findings = []
        for CheckClass in self.CHECKS:
            instance = CheckClass(self.connector)
            if check_ids and instance.rule_id not in check_ids:
                continue
            console.print(f"  [dim]Running[/dim] [bold]{instance.rule_id}[/bold] — {instance.title}")
            try:
                results = instance.run()
                self.findings.extend(results)
            except Exception as e:
                console.print(f"    [red]✗ Unexpected error:[/red] {e}")
        return self.findings


# ──────────────────────────────────────────────
# 6. REPORTING
# ──────────────────────────────────────────────

class CSPMReporter:
    """Rich console + JSON + YAML export."""

    SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

    def __init__(self, findings: list[Finding]):
        self.findings = findings

    # ── Summary table ──────────────────────────

    def print_summary(self):
        total  = len(self.findings)
        failed = [f for f in self.findings if f.status == Status.FAIL]
        passed = [f for f in self.findings if f.status == Status.PASS]
        errors = [f for f in self.findings if f.status == Status.ERROR]

        console.rule("[bold blue]CSPM Scan Summary")
        console.print(f"\nTotal checks : [bold]{total}[/bold]")
        console.print(f"  ✅ Passed  : [green]{len(passed)}[/green]")
        console.print(f"  ❌ Failed  : [red]{len(failed)}[/red]")
        console.print(f"  ⚠️  Errors  : [yellow]{len(errors)}[/yellow]")
        score = round((len(passed) / total) * 100, 1) if total else 0
        color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        console.print(f"\n[bold]Security Score: [{color}]{score}%[/{color}][/bold]\n")

    # ── Detailed findings table ─────────────────

    def print_findings(self, status_filter: Optional[Status] = None):
        subset = [f for f in self.findings if not status_filter or f.status == status_filter]
        subset.sort(key=lambda x: self.SEVERITY_ORDER.index(x.severity))

        table = Table(
            title="Findings",
            box=box.ROUNDED,
            show_lines=True,
            highlight=True,
        )
        table.add_column("Rule ID",    style="dim",    width=10)
        table.add_column("Severity",                   width=10)
        table.add_column("Status",                     width=8)
        table.add_column("Resource",                   width=30)
        table.add_column("Description",                width=60)

        for f in subset:
            sev_color = SEVERITY_COLOR.get(f.severity, "white")
            status_str = (
                "[green]✅ PASS[/green]"   if f.status == Status.PASS  else
                "[red]❌ FAIL[/red]"       if f.status == Status.FAIL  else
                "[yellow]⚠ ERROR[/yellow]"
            )
            table.add_row(
                f.rule_id,
                f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                status_str,
                f.resource_id,
                f.description,
            )
        console.print(table)

    # ── Remediation guide ──────────────────────

    def print_remediation(self):
        failed = [f for f in self.findings if f.status == Status.FAIL]
        if not failed:
            console.print("[green]No failed checks — nothing to remediate![/green]")
            return
        console.rule("[bold red]Remediation Guide")
        for f in failed:
            sev_color = SEVERITY_COLOR.get(f.severity, "white")
            console.print(f"\n[bold]{f.rule_id}[/bold] — [{sev_color}]{f.severity.value}[/{sev_color}]")
            console.print(f"  Resource  : {f.resource_id}")
            console.print(f"  Issue     : {f.description}")
            console.print(f"  [bold cyan]Fix[/bold cyan]       : {f.remediation}")

    # ── Export ─────────────────────────────────

    def export_json(self, path: str = "cspm_report.json"):
        with open(path, "w") as fh:
            json.dump([asdict(f) for f in self.findings], fh, indent=2, default=str)
        console.print(f"\n[green]JSON report saved → {path}[/green]")

    def export_yaml(self, path: str = "cspm_report.yaml"):
        with open(path, "w") as fh:
            yaml.dump([asdict(f) for f in self.findings], fh, default_flow_style=False)
        console.print(f"[green]YAML report saved → {path}[/green]")


# ──────────────────────────────────────────────
# 7. ENTRY POINT
# ──────────────────────────────────────────────

def main():
    console.rule("[bold blue]☁  Cloud Security Posture Management (CSPM)")
    console.print()

    # ── Configure ──────────────────────────────
    # Change profile/region as needed.
    # Set profile=None to use default credential chain (env vars, ~/.aws/credentials, IAM role)
    connector = AWSConnector(profile=None, region="us-east-1")

    try:
        account_id = connector.get_account_id()
        console.print(f"[bold]Account ID :[/bold] {account_id}")
        console.print(f"[bold]Region     :[/bold] {connector.region}\n")
    except Exception as e:
        console.print(f"[red]Failed to authenticate: {e}[/red]")
        return

    # ── Scan ───────────────────────────────────
    console.print("[bold]Running security checks...[/bold]\n")
    scanner  = CSPMScanner(connector)
    findings = scanner.run()
    # To run only specific checks:
    # findings = scanner.run(check_ids=["IAM_001", "S3_001", "EC2_001"])

    # ── Report ─────────────────────────────────
    reporter = CSPMReporter(findings)
    reporter.print_summary()
    reporter.print_findings(status_filter=Status.FAIL)   # Show only failures
    # reporter.print_findings()                          # Show all
    reporter.print_remediation()

    # ── Export ─────────────────────────────────
    reporter.export_json("cspm_report.json")
    reporter.export_yaml("cspm_report.yaml")


if __name__ == "__main__":
    main()