import boto3
from config.settings import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
from colorama import Fore, init

init(autoreset=True)

def get_iam_client():
    return boto3.client(
        'iam',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )

def scan_iam():
    print(Fore.CYAN + "\n[AutoShield AI] Scanning IAM Users...\n")
    client = get_iam_client()
    findings = []

    try:
        users = client.list_users().get('Users', [])

        if not users:
            print(Fore.YELLOW + "No IAM users found.")
            return findings

        for user in users:
            username = user['UserName']
            issues = []

            # Check MFA
            mfa_devices = client.list_mfa_devices(UserName=username).get('MFADevices', [])
            if not mfa_devices:
                issues.append("MFA NOT ENABLED ❌")

            # Check access keys age
            keys = client.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
            for key in keys:
                import datetime
                created = key['CreateDate'].replace(tzinfo=None)
                age = (datetime.datetime.now(datetime.timezone.utc) - created.replace(tzinfo=datetime.timezone.utc)).days
                if age > 90:
                    issues.append(f"ACCESS KEY OLD ({age} days) ❌")

            # Check admin policies
            attached = client.list_attached_user_policies(UserName=username).get('AttachedPolicies', [])
            for policy in attached:
                if 'Admin' in policy['PolicyName']:
                    issues.append(f"ADMIN POLICY ATTACHED: {policy['PolicyName']} ⚠️")

            if issues:
                print(Fore.RED + f"  [RISK] User: {username}")
                for issue in issues:
                    print(Fore.RED + f"    → {issue}")
            else:
                print(Fore.GREEN + f"  [SAFE] User: {username} ✅")

            findings.append({
                "user": username,
                "issues": issues
            })

    except Exception as e:
        print(Fore.RED + f"Error scanning IAM: {e}")

    return findings

if __name__ == "__main__":
    scan_iam()