import boto3
from config.settings import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
from colorama import Fore, init

init(autoreset=True)

def get_ec2_client():
    return boto3.client(
        'ec2',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )

def scan_security_groups():
    print(Fore.CYAN + "\n[AutoShield AI] Scanning Security Groups...\n")
    client = get_ec2_client()
    findings = []

    try:
        sgs = client.describe_security_groups().get('SecurityGroups', [])

        if not sgs:
            print(Fore.YELLOW + "No Security Groups found.")
            return findings

        for sg in sgs:
            sg_name = sg.get('GroupName', 'Unknown')
            sg_id = sg.get('GroupId', 'Unknown')
            issues = []

            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 0)

                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')

                    if cidr == '0.0.0.0/0':
                        # Check dangerous ports
                        if from_port == 22:
                            issues.append("SSH OPEN TO WORLD (Port 22) ❌")
                        elif from_port == 3389:
                            issues.append("RDP OPEN TO WORLD (Port 3389) ❌")
                        elif from_port == 0 and to_port == 0:
                            issues.append("ALL TRAFFIC OPEN TO WORLD ❌")
                        else:
                            issues.append(f"PORT {from_port}-{to_port} OPEN TO WORLD ⚠️")

            if issues:
                print(Fore.RED + f"  [RISK] Security Group: {sg_name} ({sg_id})")
                for issue in issues:
                    print(Fore.RED + f"    → {issue}")
            else:
                print(Fore.GREEN + f"  [SAFE] Security Group: {sg_name} ({sg_id}) ✅")

            findings.append({
                "sg_name": sg_name,
                "sg_id": sg_id,
                "issues": issues
            })

    except Exception as e:
        print(Fore.RED + f"Error scanning Security Groups: {e}")

    return findings

if __name__ == "__main__":
    scan_security_groups()