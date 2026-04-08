from colorama import Fore, init

init(autoreset=True)

# Risk scoring rules
RISK_SCORES = {
    "PUBLIC ACL DETECTED": 95,
    "ALL TRAFFIC OPEN TO WORLD": 90,
    "SSH OPEN TO WORLD (Port 22)": 85,
    "RDP OPEN TO WORLD (Port 3389)": 85,
    "ADMIN POLICY ATTACHED": 80,
    "MFA NOT ENABLED": 65,
    "NO ENCRYPTION": 60,
    "ACCESS KEY OLD": 50,
    "VERSIONING DISABLED": 35,
}

# AI Recommendations
RECOMMENDATIONS = {
    "PUBLIC ACL DETECTED": "Immediately disable public ACL. Enable Block Public Access on S3 bucket.",
    "ALL TRAFFIC OPEN TO WORLD": "Restrict Security Group rules. Allow only necessary ports and IPs.",
    "SSH OPEN TO WORLD (Port 22)": "Restrict SSH access to specific IP ranges only.",
    "RDP OPEN TO WORLD (Port 3389)": "Restrict RDP access to specific IP ranges only.",
    "ADMIN POLICY ATTACHED": "Follow least privilege principle. Remove unnecessary admin permissions.",
    "MFA NOT ENABLED": "Enable MFA for all IAM users immediately.",
    "NO ENCRYPTION": "Enable server-side encryption on S3 bucket.",
    "ACCESS KEY OLD": "Rotate access keys every 90 days as best practice.",
    "VERSIONING DISABLED": "Enable versioning to protect against accidental deletion.",
}

def get_risk_score(issue):
    for key in RISK_SCORES:
        if key in issue:
            return RISK_SCORES[key]
    return 20

def get_recommendation(issue):
    for key in RECOMMENDATIONS:
        if key in issue:
            return RECOMMENDATIONS[key]
    return "Review and fix this security issue."

def get_risk_level(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"

def analyze_findings(findings):
    print(Fore.CYAN + "\n" + "="*50)
    print(Fore.CYAN + "   AutoShield AI — AI Risk Analysis")
    print(Fore.CYAN + "="*50)

    analyzed = []
    total_score = 0

    for finding in findings:
        issue = finding['issue']
        score = get_risk_score(issue)
        level = get_risk_level(score)
        recommendation = get_recommendation(issue)
        total_score += score

        analyzed.append({
            **finding,
            "ai_score": score,
            "ai_risk_level": level,
            "recommendation": recommendation
        })

        # Color based on level
        if level == "CRITICAL":
            color = Fore.RED
        elif level == "HIGH":
            color = Fore.YELLOW
        elif level == "MEDIUM":
            color = Fore.CYAN
        else:
            color = Fore.GREEN

        print(color + f"\n  Resource  : {finding['resource_type']} → {finding['resource']}")
        print(color + f"  Issue     : {issue}")
        print(color + f"  AI Score  : {score}/100")
        print(color + f"  Risk Level: {level}")
        print(color + f"  Fix       : {recommendation}")
        print(color + "  " + "-"*46)

    # Overall score
    if findings:
        overall = total_score // len(findings)
    else:
        overall = 0

    print(Fore.CYAN + f"\n  🤖 AI Overall Risk Score : {overall}/100")

    if overall >= 80:
        print(Fore.RED + "  ⚠️  CRITICAL — Immediate action required!")
    elif overall >= 60:
        print(Fore.YELLOW + "  ⚠️  HIGH — Fix issues soon!")
    elif overall >= 40:
        print(Fore.CYAN + "  ⚠️  MEDIUM — Review and fix issues.")
    else:
        print(Fore.GREEN + "  ✅  LOW — Good security posture!")

    print(Fore.CYAN + "\n" + "="*50 + "\n")

    return analyzed

if __name__ == "__main__":
    from detector.detector import run_full_scan
    findings = run_full_scan()
    analyze_findings(findings)