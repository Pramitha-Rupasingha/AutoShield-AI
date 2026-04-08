import boto3
from config.settings import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
from colorama import Fore, init

init(autoreset=True)

def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )

def get_ec2_client():
    return boto3.client(
        'ec2',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )

def fix_s3_versioning(bucket_name):
    try:
        client = get_s3_client()
        client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        print(Fore.GREEN + f"  ✅ Fixed: S3 Versioning enabled → {bucket_name}")
        return True
    except Exception as e:
        print(Fore.RED + f"  ❌ Failed to fix versioning: {e}")
        return False

def fix_s3_public_access(bucket_name):
    try:
        client = get_s3_client()
        client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print(Fore.GREEN + f"  ✅ Fixed: S3 Public Access blocked → {bucket_name}")
        return True
    except Exception as e:
        print(Fore.RED + f"  ❌ Failed to fix public access: {e}")
        return False

def fix_sg_ssh(sg_id):
    try:
        client = get_ec2_client()
        client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )
        print(Fore.GREEN + f"  ✅ Fixed: SSH port 22 closed → {sg_id}")
        return True
    except Exception as e:
        print(Fore.RED + f"  ❌ Failed to fix SSH: {e}")
        return False

def fix_sg_rdp(sg_id):
    try:
        client = get_ec2_client()
        client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 3389,
                'ToPort': 3389,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )
        print(Fore.GREEN + f"  ✅ Fixed: RDP port 3389 closed → {sg_id}")
        return True
    except Exception as e:
        print(Fore.RED + f"  ❌ Failed to fix RDP: {e}")
        return False

def auto_remediate(analyzed_findings):
    print(Fore.CYAN + "\n" + "="*50)
    print(Fore.CYAN + "   AutoShield AI — Auto Remediation")
    print(Fore.CYAN + "="*50)

    fixed = 0
    skipped = 0

    for finding in analyzed_findings:
        issue = finding['issue']
        resource = finding['resource']
        resource_type = finding['resource_type']
        risk_level = finding['ai_risk_level']

        print(Fore.CYAN + f"\n  Processing: {resource_type} → {resource}")
        print(Fore.CYAN + f"  Issue     : {issue}")
        print(Fore.CYAN + f"  Risk Level: {risk_level}")

        # Auto fix based on issue type
        if "VERSIONING DISABLED" in issue and resource_type == "S3":
            if fix_s3_versioning(resource):
                fixed += 1
            else:
                skipped += 1

        elif "PUBLIC ACL DETECTED" in issue and resource_type == "S3":
            if fix_s3_public_access(resource):
                fixed += 1
            else:
                skipped += 1

        elif "SSH OPEN TO WORLD" in issue and resource_type == "SecurityGroup":
            if fix_sg_ssh(resource):
                fixed += 1
            else:
                skipped += 1

        elif "RDP OPEN TO WORLD" in issue and resource_type == "SecurityGroup":
            if fix_sg_rdp(resource):
                fixed += 1
            else:
                skipped += 1

        else:
            print(Fore.YELLOW + f"  ⚠️  Manual fix required → {issue}")
            skipped += 1

    # Summary
    print(Fore.CYAN + "\n" + "="*50)
    print(Fore.CYAN + "   Auto Remediation Summary")
    print(Fore.CYAN + "="*50)
    print(Fore.GREEN + f"\n  ✅ Auto Fixed : {fixed}")
    print(Fore.YELLOW + f"  ⚠️  Manual Fix : {skipped}")
    print(Fore.CYAN + f"  📊 Total      : {fixed + skipped}")
    print(Fore.CYAN + "\n" + "="*50 + "\n")

    return fixed, skipped

if __name__ == "__main__":
    from detector.detector import run_full_scan
    from ai_engine.risk_scorer import analyze_findings
    findings = run_full_scan()
    analyzed = analyze_findings(findings)
    auto_remediate(analyzed)