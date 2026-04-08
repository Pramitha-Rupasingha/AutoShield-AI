from scanner.s3_scanner import scan_s3_buckets
from scanner.iam_scanner import scan_iam
from scanner.sg_scanner import scan_security_groups
from colorama import Fore, init

init(autoreset=True)

# Risk level assign karanna
def assign_risk(issue):
    high_keywords = ["PUBLIC ACL", "ALL TRAFFIC", "SSH OPEN", "RDP OPEN", "ADMIN POLICY"]
    medium_keywords = ["MFA NOT ENABLED", "NO ENCRYPTION", "PORT"]
    low_keywords = ["VERSIONING DISABLED", "ACCESS KEY OLD"]

    for keyword in high_keywords:
        if keyword in issue:
            return "HIGH"
    for keyword in medium_keywords:
        if keyword in issue:
            return "MEDIUM"
    for keyword in low_keywords:
        if keyword in issue:
            return "LOW"
    return "LOW"

def run_full_scan():
    print(Fore.CYAN + "\n" + "="*50)
    print(Fore.CYAN + "   AutoShield AI — Full Security Scan")
    print(Fore.CYAN + "="*50)

    all_findings = []

    # Run all scanners
    s3_findings = scan_s3_buckets()
    iam_findings = scan_iam()
    sg_findings = scan_security_groups()

    # Process S3 findings
    for item in s3_findings:
        for issue in item['issues']:
            risk = assign_risk(issue)
            all_findings.append({
                "resource_type": "S3",
                "resource": item['bucket'],
                "issue": issue,
                "risk": risk
            })

    # Process IAM findings
    for item in iam_findings:
        for issue in item['issues']:
            risk = assign_risk(issue)
            all_findings.append({
                "resource_type": "IAM",
                "resource": item['user'],
                "issue": issue,
                "risk": risk
            })

    # Process Security Group findings
    for item in sg_findings:
        for issue in item['issues']:
            risk = assign_risk(issue)
            all_findings.append({
                "resource_type": "SecurityGroup",
                "resource": item['sg_name'],
                "issue": issue,
                "risk": risk
            })

    # Summary
    print(Fore.CYAN + "\n" + "="*50)
    print(Fore.CYAN + "   AutoShield AI — Scan Summary")
    print(Fore.CYAN + "="*50)

    high = [f for f in all_findings if f['risk'] == 'HIGH']
    medium = [f for f in all_findings if f['risk'] == 'MEDIUM']
    low = [f for f in all_findings if f['risk'] == 'LOW']

    print(Fore.RED + f"\n  🔴 HIGH Risk Issues   : {len(high)}")
    print(Fore.YELLOW + f"  🟡 MEDIUM Risk Issues : {len(medium)}")
    print(Fore.GREEN + f"  🟢 LOW Risk Issues    : {len(low)}")
    print(Fore.CYAN + f"\n  📊 Total Issues Found : {len(all_findings)}")

    if all_findings:
        print(Fore.CYAN + "\n" + "="*50)
        print(Fore.CYAN + "   Detailed Findings")
        print(Fore.CYAN + "="*50)
        for f in all_findings:
            color = Fore.RED if f['risk'] == 'HIGH' else Fore.YELLOW if f['risk'] == 'MEDIUM' else Fore.GREEN
            print(color + f"\n  [{f['risk']}] {f['resource_type']} → {f['resource']}")
            print(color + f"    Issue: {f['issue']}")

    print(Fore.CYAN + "\n" + "="*50 + "\n")

    return all_findings

if __name__ == "__main__":
    run_full_scan()