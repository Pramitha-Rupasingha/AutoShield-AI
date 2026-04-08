from colorama import Fore, Style, init
from detector.detector import run_full_scan
from ai_engine.risk_scorer import analyze_findings
from logs.audit_logger import save_log, view_logs
from remediation.remediator import auto_remediate

init(autoreset=True)

def print_banner():
    print(Fore.CYAN + """
    ╔══════════════════════════════════════════════╗
    ║                                              ║
    ║        AutoShield AI  🛡️                     ║
    ║   AI-Powered Cloud Security Automation       ║
    ║                                              ║
    ╚══════════════════════════════════════════════╝
    """)

def main_menu():
    print(Fore.CYAN + "\n  Select an option:\n")
    print(Fore.WHITE + "  [1] Run Full Security Scan")
    print(Fore.WHITE + "  [2] Run Scan + AI Analysis")
    print(Fore.WHITE + "  [3] Run Scan + AI Analysis + Auto Remediation")
    print(Fore.WHITE + "  [4] View Audit Log History")
    print(Fore.WHITE + "  [5] Exit")
    print()
    choice = input(Fore.CYAN + "  Enter choice (1-5): ")
    return choice

def run():
    print_banner()

    while True:
        choice = main_menu()

        if choice == '1':
            run_full_scan()

        elif choice == '2':
            findings = run_full_scan()
            analyze_findings(findings)

        elif choice == '3':
            print(Fore.YELLOW + "\n  ⚠️  Auto Remediation will fix issues automatically!")
            confirm = input(Fore.YELLOW + "  Are you sure? (yes/no): ")
            if confirm.lower() == 'yes':
                findings = run_full_scan()
                analyzed = analyze_findings(findings)
                save_log(analyzed)
                auto_remediate(analyzed)
            else:
                print(Fore.YELLOW + "  Remediation cancelled.")

        elif choice == '4':
            view_logs()

        elif choice == '5':
            print(Fore.CYAN + "\n  👋 AutoShield AI — Goodbye!\n")
            break

        else:
            print(Fore.RED + "\n  ❌ Invalid choice. Try again.")

if __name__ == "__main__":
    run()