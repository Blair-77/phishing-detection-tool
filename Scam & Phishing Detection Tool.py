# Scam & Phishing Email Detection Tool
# Author Blair Davidson
# Rule based phishing detection & educational feedback system

import os
import re
import sys
import ctypes
from dataclasses import dataclass
from typing import List, Tuple
from urllib.parse import urlparse

# ANSI colour support & enables ANSI colour codes 
def _enable_windows_ansi() -> None:
    if os.name != "":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass

# Checks if the terminal supports coloured outputs
def supports_colour() -> bool:
    return sys.stdout.isatty()

# Enable ANSI colour on Windows 
_enable_windows_ansi()
USE_COLOUR = supports_colour()

# ANSI escape codes for styling 
RESET = "\033[0m" if USE_COLOUR else ""
BOLD = "\033[1m" if USE_COLOUR else ""
RED = "\033[91m" if USE_COLOUR else ""
YELLOW = "\033[93m" if USE_COLOUR else ""
GREEN = "\033[92m" if USE_COLOUR else ""
CYAN = "\033[96m" if USE_COLOUR else ""
MAGENTA = "\033[95m" if USE_COLOUR else ""

# Applies the colours
def colour(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if USE_COLOUR else text

# --Data structures--
@dataclass
class Finding:
    title: str
    evidence: str
    why_it_matters: str
    what_to_do: str
    tip_next_time: str
    weight: int


# Regular expression used to detect URLs in email text
URL_REGEX = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"')]+)""")

# Extracts all URLs from the email text
# Finds URL patterns using regex
# Cleans trailing punctuation
# Normalises links to full URLs
# Removes duplicates
def extract_urls(text: str) -> List[str]:
    urls = []
    for match in URL_REGEX.findall(text):
        url = match.strip().rstrip(".,;:!?)\"]}")
        if url.lower().startswith("www."):
            url = "http://" + url
        urls.append(url)
    return list(dict.fromkeys(urls))

# Safely extracts the domain hostname from a URL & returns empty string if parsing fails
def safe_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""

# Counts the number of subdomains in a domain & detects suspiciously complex or misleading URLs
def count_subdomains(domain: str) -> int:
    if not domain:
        return 0
    parts = domain.split(".")
    return max(0, len(parts) - 2)

# Checks if any phrases from a list appear in the text & returns all matching phrases 
def contains_any(text: str, phrases: List[str]) -> List[str]:
    found = []
    lowered = text.lower()
    for p in phrases:
        if p.lower() in lowered:
            found.append(p)
    return found

# --Detection rules for phishing indicators--
# Known URL shortening services 
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"
}

# Suspicious toplevel domains 
SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".top", ".xyz", ".click", ".link", ".work", ".country"
}

# Urgency phrases to pressure users
URGENCY_PHRASES = [
    "immediately", "urgent", "act now", "within 24 hours", "within 48 hours", "within 12 hours", "Within",
    "final warning", "final notice", "last chance", "asap", "limited time", "expires today",
    "action required", "confirm now", "verify now", "respond today", "failure to act",
    "without delay", "today only", "complete now", "required immediately","failure to reply"
]

# Threat based phrases to create fear
THREAT_PHRASES = [
    "account will be closed", "account suspended", "locked", "legal action", "penalty",
    "unauthorized login", "security alert", "unusual activity", "disabled", "deactivated",
    "service interruption", "service interrupted", "mailbox will be suspended", "closure of your account", "remain locked",
    "quota limit", "over quota", "temporarily locked", "suspended for security reasons",
    "access will be removed", "account disabled", "permanent closure", "cancelled"
]

# Credential related phrases used in phishing
CREDENTIAL_PHRASES = [
    "verify your account", "confirm your password", "reset your password", "login to", "sign in",
    "update your payment", "billing information", "bank details", "security check",
    "confirm account", "confirm your identity", "verify your identity", "account details",
    "credentials", "update your account", "confirm your banking information",
    "restore access", "security verification", "account verification", "log in",
    "confirm your details", "verify your details"
]

# Financial phrases used as bait
PAYMENT_PHRASES = [
    "invoice", "payment", "refund", "transaction", "wire transfer", "gift card", "crypto", "bitcoin",
    "salary", "wages", "banking information", "late fees", "charges", "billing issue",
    "overdue", "outstanding payment", "subscription", "payroll", "pending payment", "payment failed"
]

# Attachment phrases for potential malware delivery
ATTACHMENT_PHRASES = [
    "attached invoice", "invoice attached", "see attached", "download the attached",
    "attached file", "attachment", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip",
    "open the attachment", "download invoice", "attached document"
]

# --Language based phishing detection--
# Analyses the text for common phishing  patterns & returns findings based on detected
def rule_language_signals(email_text: str) -> List[Finding]:
    findings: List[Finding] = []

# Detect the urgency phrases 
    urgency = contains_any(email_text, URGENCY_PHRASES)
    if urgency:
        findings.append(Finding(
            title="Urgency / time pressure language",
            evidence=f"Found: {', '.join(urgency[:6])}{'...' if len(urgency) > 6 else ''}",
            why_it_matters="Phishing emails often create urgency so you act before thinking or verifying.",
            what_to_do="Pause. Verify the request through an official channel (e.g. Company website or known phone number).",
            tip_next_time="Be cautious of messages demanding immediate action or deadlines.",
            weight=10
        )
    )
    
# Detect the threatening or fear language 
    threats = contains_any(email_text, THREAT_PHRASES)
    if threats:
        findings.append(Finding(
            title="Threatening language & account scare tactics",
            evidence=f"Found: {', '.join(threats[:6])}{'...' if len(threats) > 6 else ''}",
            why_it_matters="Attackers commonly use fear tatics (account closure, penalties, disablement) to manipulate victims.",
            what_to_do="Do not click links in the message. Navigate to the service directly in your browser and check there.",
            tip_next_time="Scare tactics combined with links or sign-in requests are a common phishing pattern.",
            weight=12
        )
    )
    
# Detect the credential requests
    creds = contains_any(email_text, CREDENTIAL_PHRASES)
    if creds:
        findings.append(Finding(
            title="Credential & verification request",
            evidence=f"Found: {', '.join(creds[:6])}{'...' if len(creds) > 6 else ''}",
            why_it_matters="Requests to log in, verify details or reset passwords are prime phishing themes.",
            what_to_do="If this concerns a real account, manually type the official site address and sign in there.",
            tip_next_time="Avoid signing in via email links, use bookmarks or trusted navigations.",
            weight=16
        )
    )

# Detects financial and payment related baiting 
    pay = contains_any(email_text, PAYMENT_PHRASES)
    if pay:
        findings.append(Finding(
            title="Payment & finance related trigger words",
            evidence=f"Found: {', '.join(pay[:6])}{'...' if len(pay) > 6 else ''}",
            why_it_matters="Financial themes (invoices, refunds, charges) are frequently used to lure clicks or attachment opens.",
            what_to_do="Confirm with the sender using a known contact method, especially before paying or opening attachments.",
            tip_next_time="Treat unexpected invoices, refunds, salary or billing emails as suspicious until verified.",
            weight=10
        )
    )
# Returns all the detected language findings
    return findings

# Detects wording that contains attachments or downloadable files for identifying malicious documents or malware delivery
def rule_attachment_signals(email_text: str) -> List[Finding]:
    found = contains_any(email_text, ATTACHMENT_PHRASES)
    if not found:
        return []
    
    return [Finding(
        title="Attachment & file-delivery language detected",
        evidence=f"Found: {', '.join(found[:6])}{'...' if len(found) > 6 else ''}",
        why_it_matters="Phishing emails commonly use attachments or downloadable files to deliver malware or to trick users into opening harmful documents.",
        what_to_do="Do not open unexpected attachments until the sender and reason for the file have been verified.",
        tip_next_time="Unexpected invoices, ZIP files and document attachments are common phishing techniques.",
        weight=10 #Moderate risk indicator
    )
]

# Analyses the extracted URLs for any suspicious characteristics and adds separate findings that contributes to the overall risk score
def rule_url_signals(urls: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    for url in urls:
        domain = safe_domain(url)

# Flags the known URL shorteners
        if domain in URL_SHORTENERS:
            findings.append(Finding(
                title="URL shortener detected",
                evidence=f"{url}",
                why_it_matters="Shortened links hide the real destination making it easier to disguise malicious sites.",
                what_to_do="Do not click on the link. Expand the link using a safe link expander or verify via the official site navigation.",
                tip_next_time="Short links in accounts, security or payment emails are often a strong warning sign.",
                weight=15 #High risk indicator
            )
        )
            
# Flags raw IP address instead of normal domain names
        if re.search(r"(?:(?:\d{1,3}\.){3}\d{1,3})", domain or ""):
            findings.append(Finding(
                title="Link uses a raw IP address",
                evidence=f"{url}",
                why_it_matters="Legitimate services rarely ask you to log in via an IP address link, however attackers often do.",
                what_to_do="Avoid clicking. If you need the service go to the official domain manually.",
                tip_next_time="Prefer known domains as IP links are suspicious for login & payment flows.",
                weight=18# Very strong indicator
            )
        )
            
# Flags any URLs containing @ 
        if "@" in url:
            findings.append(Finding(
                title="Suspicious '@' in URLs",
                evidence=f"{url}",
                why_it_matters="In URLs, '@' can be used to mislead users about the real destination domain.",
                what_to_do="Do not click. Treat it as high risk and verify using official navigation means.",
                tip_next_time="The true destination is after the '@', not before it.",
                weight=14 #High risk indicator
            )
        )
            
# Flags unusually long URLs
        if len(url) >= 80:
            findings.append(Finding(
                title="Very long URLs",
                evidence=f"{url[:120]}{'...' if len(url) > 120 else ''}",
                why_it_matters="Overly long URLs can obscure the true domain & path and can include tracking or deception.",
                what_to_do="Inspect the domain carefully or avoid the link and navigate manually.",
                tip_next_time="Long complex links in urgent emails deserve extra scrutiny.",
                weight=6 #Lower weight heuristic indicator
            )
        )

# Flags domains with many any subdomains
        sub_count = count_subdomains(domain)
        if sub_count >= 3:
            findings.append(Finding(
                title="Many subdomains in the link domain",
                evidence=f"Domain: {domain} (subdomains: {sub_count})",
                why_it_matters="Attackers may create confusing subdomains to mimic legitimate brands.",
                what_to_do="Check the registered domain carefully (for example, example.com) and verify it's correct.",
                tip_next_time="Phishing often relys on lookalike or confusing subdomains.",
                weight=8 #Moderate heuristic indicator
            )
        )

# Flags suspicious toplevel domains
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append(Finding(
                    title="Potentially suspicious top-level domain (heuristic)",
                    evidence=f"{domain}",
                    why_it_matters="Some TLDs are more frequently abused in scams; this alone does not prove phishing.",
                    what_to_do="Treat as suspicious if combined with urgency or credential requests. Verify independently.",
                    tip_next_time="Judge the full context: sender, request type, and link destination.",
                    weight=6 #Lower weight indicator
                )
            )
                break
# Returns all URL based phishing findings
    return findings

# Detects any generic greeting text
def rule_generic_greeting(email_text: str) -> List[Finding]:
    greetings = [
        "dear customer", "dear user", "valued customer",
        "hello user", "dear account holder", "dear student"
    ]
    found = contains_any(email_text, greetings)
    if found:
        return [Finding(
            title="Generic greeting (no personalisation)",
            evidence=f"Found: {', '.join(found)}",
            why_it_matters="Many phishing emails avoid personal details to scale to more victims.",
            what_to_do="Be extra cautious if the email asks you to click a link, sign in or pay.",
            tip_next_time="Legitimate account emails often include your name or partial account identifiers.",
            weight=5 #Low risk indicator
        )
    ]
    return []

# -- Scoring & reporting --

# Converts the total risk score into a classification level
# Higher scores indicate a higher likelihood of phishing
def score_to_level(score: int) -> str:
    if score >= 61:
        return "PHISHING / VERY HIGH RISK"
    if score >= 31:
        return "HIGH RISK"
    if score >= 16:
        return "MEDIUM RISK"
    if score >= 6:
        return "LOW RISK"
    return "APPEARS SAFE / HIGHLY UNLIKELY"

# Formats the classification label with colours for output & improves readability & highlighted risk severity 
def graded_label(level: str) -> str:
    if level == "PHISHING / VERY HIGH RISK":
        return colour("[PHISHING]", RED) + " " + colour(level, RED)
    if level == "HIGH RISK":
        return colour("[HIGH RISK]", MAGENTA if USE_COLOUR else RED) + " " + colour(level, MAGENTA if USE_COLOUR else RED)
    if level == "MEDIUM RISK":
        return colour("[MEDIUM RISK]", YELLOW) + " " + colour(level, YELLOW)
    if level == "LOW RISK":
        return colour("[LOW RISK]", GREEN) + " " + colour(level, GREEN)
    return colour("[APPEARS SAFE]", CYAN) + " " + colour(level, CYAN)

# Provides user friendly explanations while supporting the educational purpose of the tool for each risk level
def risk_assessment_text(level: str) -> List[str]:
    if level == "APPEARS SAFE / HIGHLY UNLIKELY":
        return [
            "This email appears to be mostly safe based on the current indicators.",
            "No significant phishing patterns were detected by the current rules.",
            "However, always stay on the side of caution with unexpected links, attachments or requests."
        ]
    if level == "LOW RISK":
        return [
            "This email appears to be a low risk based on the current indicators.",
            "A small number of the element indicators were detected here that can appear in phishing emails, but on their own they do not strongly indicate malicious intent.",
            "It is still good practice to verify links, attachments or unexpected requests before interacting."
        ]
    if level == "MEDIUM RISK":
        return [
            "This email contains several suspicious indicators that may suggest phishing behaviour.",
            "The email may still be legitimate, but caution is advised.",
            "Verify the sender and request through an official channel before clicking links or opening attachments."
        ]
    if level == "HIGH RISK":
        return [
            "This email contains multiple strong phishing indicators and should be treated as a high risk.",
            "The combination of findings makes the message more concerning than the normal low confidence warnings.",
            "Do not click links or open attachments until the request has been independently verified."
        ]
    return [
        "This email contains numerous strong phishing indicators and is highly likely to be malicious.",
        "The score and combination of findings strongly suggest phishing or scam behaviours.",
        "Do not interact with the email. Report it and verify the request using an official method if needed."
    ]

# Main function for analysis for email scanner by combining all rule based checks, final score calculation and risk level
def analyze_email(email_text: str) -> Tuple[int, str, List[Finding], List[str]]:
# Extracts any URLs found for further inspection
    urls = extract_urls(email_text)

 # Runs all phishing detection rules and collects the findings
    findings: List[Finding] = []
    findings += rule_language_signals(email_text)
    findings += rule_attachment_signals(email_text)
    findings += rule_generic_greeting(email_text)
    findings += rule_url_signals(urls)

# Calculates the total phishing risk score, converts to a risk calculation and returns the score  
    score = sum(f.weight for f in findings)
    level = score_to_level(score)
    return score, level, findings, urls

# Displays the final scan results in a readable format that includes classification, score, findings, educational feedback, and recommended next steps
def print_report(score: int, level: str, findings: List[Finding], urls: List[str]) -> None:
    header_line = "=" * 70
    print("\n" + header_line)
    print(colour(BOLD + "SCAN RESULTS" + RESET if USE_COLOUR else "SCAN RESULTS", CYAN))
    print(f"Classification: {graded_label(level)}")
    print(f"Risk score: {score}")
    print(header_line)

# Display any extracted URLs 
    if urls:
        print("\nExtracted URLs:")
        for u in urls:
            print(f" - {u}")

# If nothing suspicious is detected still provide cautionary guidance to the user
    if not findings:
        print("\nNo obvious phishing indicators were detected by the current rules.")
        print("That does NOT guarantee safety, sophisticated attacks can evade simple checks.")
        print("\nRisk Assessment:")
        for line in risk_assessment_text(level):
            print(f" - {line}")
        print("\nSafe practice:")
        print(" Verify unexpected requests via official channels")
        print(" Dont sign in through email links, type the official site manually instead")
        return

# Displays each finding with evidence, explanation and user advice
    print("\nFindings & Educational Feedback:")
    for i, f in enumerate(findings, 1):
        print(f"\n[{i}] {f.title} (+{f.weight})")
        print(f"Evidence: {f.evidence}")
        print(f"Why it matters: {f.why_it_matters}")
        print(f"What to do: {f.what_to_do}")
        print(f"Tip for next time: {f.tip_next_time}")

# Displays the summary risk assessment based on overall score
    print("\nRisk Assessment:")
    for line in risk_assessment_text(level):
        print(f" - {line}")

# Provides the recommended next steps depending on the detected risk level
    print("\nRecommended next steps (general):")
    if level == "APPEARS SAFE / HIGHLY UNLIKELY":
        print(" - Continue to use normal safe email practices.")
        print(" - Verify unexpected requests or unfamiliar links before interacting.")
    elif level == "LOW RISK":
        print(" - Be cautious with any links or attachments, especially if they are unexpected.")
        print(" - Verify the request through the IT team or a known contact method if unsure.")
    elif level == "MEDIUM RISK":
        print(" - Avoid clicking links or opening attachments until verified.")
        print(" - Contact the sender through an official or known channel to confirm the legitimacy.")
    elif level == "HIGH RISK":
        print(" - Do not click links or open attachments until independently verified by the appropriate individual or by the  IT team.")
        print(" - Treat the message as potentially malicious and report it if in an organisation.")
    else:
        print(" - Do not click on the links or open any attachments.")
        print(" - Verify the request via a trusted method (official website or known phone numbers).")
        print(" - If this is in an organisation: report to IT/Security with the email content & headers if available.")
    print(header_line + "\n")

# -- Input modes --
# Allows for the user to paste email text directly into the terminal and ends when the user types 'END' on a new line
def read_email_from_paste() -> str:
    print("Paste your email content below (type 'END' to finish and begin the scan):")
    email_lines = []

    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        email_lines.append(line)

    return "\n".join(email_lines).strip()

# Allows the user to enter in the email by dragging in the text file or pasting a file path
def read_email_from_file() -> str:
    print("Drag and drop a .txt file into this terminal, then press Enter:")
    print("Or paste the full file path manually.")
    raw_path = input().strip()

    if not raw_path:
        print("\nNo file path detected.\n")
        return ""

    file_path = raw_path.strip()

# Handles PowerShell drag and-drop format
    if file_path.startswith("& "):
        file_path = file_path[2:].strip()

# Remove any surrounding quotes if present
    file_path = file_path.strip('"').strip("'")

# Expands the environment vars and user home
    file_path = os.path.expandvars(os.path.expanduser(file_path))

# Checks if the file location exists before attempting to open it
    if not os.path.isfile(file_path):
        print(f"\nFile not found: {file_path}")
        print("Please check the path and try again.\n")
        return ""

# Provides a warnings for the user if the selected file is not a .txt file
    if not file_path.lower().endswith(".txt"):
        print("\nWarning: this file is not a .txt file. Attempting to read it anyway\n")

# Tries multiple encodings to improve compatibility with different text files
    encodings_to_try = ["utf-8", "utf-8-sig", "cp1252", "latin-1"]

    for enc in encodings_to_try:
        try:
            with open(file_path, "r", encoding=enc) as f:
                content = f.read().strip()
                if not content:
                    print("\nThe file was read successfully however appears to be empty.\n")
                    return ""
                return content
        except UnicodeDecodeError:
            continue
        except Exception as e:
            print(f"\nCould not read file: {e}\n")
            return ""

    print("\nCould not decode the file with common text encodings.\n")
    return ""

# Has the user to choose between paste mode and file-input mode and repeats until a valid option is selected
def choose_input_method() -> str:
    while True:
        print("Choose input method:")
        print("  1. Paste email contents")
        print("  2. Drag and drop a .txt file")

        choice = input("Enter 1 or 2: ").strip()

        if choice in ("1", "2"):
            return choice

        print("\nPlease enter 1 or 2 to proceed.\n")

# -- Main command line interface --
# Main functions that controls the programs overall flow by handling input selection, email analysis, result display, and repeated testing
def email_tool() -> None:
    print(colour("Scam & Phishing Email Detection Tool", CYAN))
    print("You can either paste email contents or drag a .txt file into the terminal.")
    print("If pasting contents, type 'END' on a new line when finished.\n")

    while True:
# Asks the user how they want to provide the email sample
        mode = choose_input_method()

# Reads email input using the chosen method
        if mode == "2":
            email_input = read_email_from_file()
        else:
            email_input = read_email_from_paste()

# Prevents any empty inputs from being analysed
        if not email_input:
            print("No email content detected. Please try again.\n")
            continue

 # Analyses the email and displays the report
        print("\nAnalyzing inputted email...\n")
        score, level, findings, urls = analyze_email(email_input)
        print_report(score, level, findings, urls)
        
# Ask the user whether they want to test another email
        while True:
            choice = input("Would you like to test another email? (yes/no): ").lower().strip()

            if choice == "yes":
                print()
                break
            elif choice == "no":
                print("\nProgram ending!")
                return
            else:
                print("Please enter yes or no to proceed.\n")
if __name__ == "__main__":
    email_tool()