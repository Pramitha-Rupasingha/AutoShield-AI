import boto3
from config.settings import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
from colorama import Fore, Style, init

init(autoreset=True)

def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )

def scan_s3_buckets():
    print(Fore.CYAN + "\n[AutoShield AI] Scanning S3 Buckets...\n")
    client = get_s3_client()
    findings = []

    try:
        buckets = client.list_buckets().get('Buckets', [])

        if not buckets:
            print(Fore.YELLOW + "No S3 buckets found.")
            return findings

        for bucket in buckets:
            bucket_name = bucket['Name']
            issues = []

            # Check public access
            try:
                acl = client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        issues.append("PUBLIC ACL DETECTED ❌")
            except Exception:
                pass

            # Check encryption
            try:
                client.get_bucket_encryption(Bucket=bucket_name)
            except Exception:
                issues.append("NO ENCRYPTION ❌")

            # Check versioning
            versioning = client.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get('Status') != 'Enabled':
                issues.append("VERSIONING DISABLED ❌")

            if issues:
                print(Fore.RED + f"  [RISK] Bucket: {bucket_name}")
                for issue in issues:
                    print(Fore.RED + f"    → {issue}")
            else:
                print(Fore.GREEN + f"  [SAFE] Bucket: {bucket_name} ✅")

            findings.append({
                "bucket": bucket_name,
                "issues": issues
            })

    except Exception as e:
        print(Fore.RED + f"Error scanning S3: {e}")

    return findings

if __name__ == "__main__":
    scan_s3_buckets()