import re
from typing import List, Dict, Any

URGENCY_PATTERNS = [
    r"\b(urgent|immediately|action required|account suspended|suspended within \d+ hours|final warning|last notice|deactivated|expire[s]? today|immediate action|unauthorized access|security breach)\b",
    r"\b(within \d+ (minutes|hours|days)|lock your account|terminated|penalty|legal action|police|lawsuit)\b",
    r"\b(power will be disconnected|electricity disconnected|service cutoff|sim blocked|sim deactivated)\b"
]

CREDENTIAL_HARVESTING_PATTERNS = [
    r"\b(verify your (account|password|identity|ssn|pin|otp|credentials|pan|aadhaar)|click here to login|update your payment|confirm your details|re-enter password)\b",
    r"\b(one-time password|otp is|do not share|enter pin|bank account details|credit card number|cvv|security code|share otp|submit otp)\b",
    r"\b(enter upi pin to receive|upi pin to claim|enter mpin|share your 6 digit)\b"
]

FINANCIAL_SCAM_PATTERNS = [
    r"\b(won a prize|congratulations|lottery winner|claim your reward|\$\d+,\d+|\$\d+ free|bitcoin|crypto investment|guaranteed return|wire transfer|gift card|cash prize|claim \$)\b",
    r"\b(refund of \$\d+|unpaid invoice|tax refund|overdue payment|loan approved|instant credit|pre-approved loan|credit limit increased)\b",
    r"\b(kbc lottery|25 lakh lottery|lucky draw winner|cashback credited|claim cashback of rs|instant cash reward)\b",
    r"\b(crypto|usdt|btc|eth|solana|airdrop|crypto giveaway|claim\s+(?:your\s+)?(?:\d+\s+)?(?:usdt|\$|rs|crypto)?\s*reward|giveaway|bonus credited)\b"
]

IMPERSONATION_PATTERNS = [
    r"\b(customer support|helpdesk|security team|bank officer|tax authority|irs|fedex|ups|dhl|amazon support|apple id|netflix billing|geek squad)\b",
    r"\b(sbi bank|hdfc bank|icici bank|axis bank|pnb bank|canara bank|bank of baroda|kotak|paytm bank|india post|electricity board|bsnl|airtel|jio)\b",
    r"\b(telegram support|telegram security|community manager|group admin|official moderator|helpdesk agent)\b"
]

KYC_AND_BANKING_SCAM_PATTERNS = [
    r"\b(kyc (suspended|expired|pending|verification required|mandatory update)|update pan card|link aadhaar|pan not linked|account will be blocked|ebanking blocked)\b",
    r"\b(sbi yono|yono account suspended|hdfc netbanking blocked|icici alert: account frozen|pnb one update)\b"
]

UTILITY_AND_DELIVERY_SCAMS = [
    r"\b(dear consumer electricity|power will be disconnected|electricity bill (unpaid|pending)|disconnected at \d{1,2}:\d{2}\s*(pm|am)|contact electricity officer)\b",
    r"\b(india post: package|parcel could not be delivered|incorrect address|update delivery address|pay rs \d+ redelivery fee)\b",
    r"\b(bijli|electricity|power|power supply).*(disconnect|kat|kaat|band|deactivat)\b",
    r"\b(bill payment|unpaid bill|pending bill|contact.*officer)\b"
]

JOB_AND_INVESTMENT_SCAMS = [
    r"\b(part[- ]time job|work from home|earn rs\.?\s*\d+[- ]\d+\s*daily|telegram task|like youtube videos and earn|daily income guaranteed|crypto trading profit)\b",
    r"\b(guaranteed\s+(?:daily\s+)?profit|double your (?:crypto|investment|btc|usdt)|vip signals?|pump and dump|usdt mining|smart contract arbitrage|forex trader|crypto expert)\b"
]

TELEGRAM_SPECIFIC_SCAMS = [
    r"\b(seed phrase|12[- ]word (?:seed\s+)?phrase|private key|recovery phrase|secret key|trust wallet|metamask validation|sync wallet|connect wallet to claim)\b",
    r"\b(prepaid task|telegram task|task code|receptionist\s*@|contact telegram|whatsapp to telegram|daily salary rs|send payment screenshot to admin)\b",
    r"\b(dm me privately|inbox me for investment|send txid|send hash|gas fee to release)\b"
]

MALICIOUS_APP_LURES = [
    r"\b(download (apk|file|app)|install anydesk|install teamviewer|quicksupport|rustdesk|sbi-update\.apk|kyc\.apk)\b"
]

HINGLISH_PATTERNS = [
    r"\b(aapka|apka|tumhara)\s+(sbi|hdfc|icici|bank|khata|account|sim|bijli)\s+(block|band|suspend|deactivate)\b",
    r"\b(turant|jaldi|aaj hi)\s+(click|update|karein|karo|sampark karein)\b",
    r"\b(bijli|electricity)\s+(kat|disconnect|band)\s+(hogi|jayegi|hoga|kar di jayegi)\b",
    r"\b(paise|rupaye|cashback)\s+(pane|lene|claim karne)\s+ke liye\s+(upi pin|pin|link)\b",
    r"\b(niche diye|click karke|apna pan card update)\b"
]

def redact_sensitive_otp(text: str) -> str:
    """
    Sanitizes sensitive OTP codes, PINs, and credentials from SMS before logging or sharing,
    adhering strictly to Privacy & Data Minimization guidelines.
    """
    if not text:
        return text

    # Mask numeric OTPs (4 to 8 digits) following phrases like 'OTP is', 'code is', 'verification code'
    sanitized = re.sub(
        r"(?i)\b(otp|code|one-time password|pin|verification code|secret key)([:\s\-is=]+)(\d{4,8})\b",
        r"\1\2[REDACTED_OTP]",
        text
    )
    # Mask standalone phrases like "Enter 6 digit OTP: 123456"
    sanitized = re.sub(
        r"(?i)\b(is\s+)(\d{4,8})(\s+for\b|\s+to\b|\.)",
        r"\1[REDACTED_OTP]\3",
        sanitized
    )
    return sanitized

def analyze_scam_rules(text: str) -> Dict[str, Any]:
    text_lower = text.lower()
    reasons: List[str] = []
    points = 0
    categories = []

    # 1. Check Urgency & Coercion
    urgency_matches = 0
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, text_lower):
            urgency_matches += 1
    if urgency_matches > 0:
        points += min(35, 25 * urgency_matches)
        reasons.append("High urgency language designed to cause panic or swift action")
        categories.append("Urgency & Coercion")

    # 2. Check Credential & OTP Harvesting
    harvest_matches = 0
    for pattern in CREDENTIAL_HARVESTING_PATTERNS:
        if re.search(pattern, text_lower):
            harvest_matches += 1
    if harvest_matches > 0:
        points += min(45, 35 * harvest_matches)
        reasons.append("Requests for sensitive credentials, OTPs, UPI PINs, or identity verification")
        categories.append("Credential & OTP Harvesting")

    # 3. Check Financial / Prize / Lottery Scams
    financial_matches = 0
    for pattern in FINANCIAL_SCAM_PATTERNS:
        if re.search(pattern, text_lower):
            financial_matches += 1
    if financial_matches > 0:
        points += min(40, 30 * financial_matches)
        reasons.append("Financial incentive, lottery/prize claim, or refund lure detected")
        categories.append("Financial & Lottery Scam")

    # 4. Check Brand & Institution Impersonation
    impersonation_matches = 0
    for pattern in IMPERSONATION_PATTERNS:
        if re.search(pattern, text_lower):
            impersonation_matches += 1
    if impersonation_matches > 0:
        points += min(30, 20 * impersonation_matches)
        reasons.append("Impersonation of trusted institutions, banks, or telecom/utility services")
        categories.append("Brand / Official Impersonation")

    # 5. Check KYC & Banking Suspension Threats (Indian Telecom Context)
    kyc_matches = 0
    for pattern in KYC_AND_BANKING_SCAM_PATTERNS:
        if re.search(pattern, text_lower):
            kyc_matches += 1
    if kyc_matches > 0:
        points += min(45, 35 * kyc_matches)
        reasons.append("Fake KYC expiry, PAN/Aadhaar unlinked threat or banking suspension alert")
        categories.append("Fake KYC & Bank Suspension")

    # 6. Check Utility / Electricity / India Post Scams
    utility_matches = 0
    for pattern in UTILITY_AND_DELIVERY_SCAMS:
        if re.search(pattern, text_lower):
            utility_matches += 1
    if utility_matches > 0:
        points += min(40, 35 * utility_matches)
        reasons.append("Utility cutoff threat (e.g., electricity disconnection) or fake delivery courier lure")
        categories.append("Utility & Delivery Scam")

    # 7. Check Job / Telegram / Investment Fraud
    job_matches = 0
    for pattern in JOB_AND_INVESTMENT_SCAMS:
        if re.search(pattern, text_lower):
            job_matches += 1
    if job_matches > 0:
        points += min(35, 30 * job_matches)
        reasons.append("Unsolicited part-time job, Telegram task, or fraudulent high-yield investment scheme")
        categories.append("Job & Investment Fraud")

    # 8. Check Malicious App (.APK / Remote Access) Lures
    app_matches = 0
    for pattern in MALICIOUS_APP_LURES:
        if re.search(pattern, text_lower):
            app_matches += 1
    if app_matches > 0:
        points += min(45, 40 * app_matches)
        reasons.append("Lures victim to download an external APK or install dangerous remote-access tools (AnyDesk/QuickSupport)")
        categories.append("Malicious App / APK Lure")

    # 9. Check Hindi / Hinglish Dialect Patterns
    hinglish_matches = 0
    for pattern in HINGLISH_PATTERNS:
        if re.search(pattern, text_lower):
            hinglish_matches += 1
    if hinglish_matches > 0:
        points += min(30, 25 * hinglish_matches)
        reasons.append("Regional Hindi/Hinglish social engineering patterns targeting Indian mobile subscribers")
        categories.append("Regional / Hinglish Social Engineering")

    # 10. Check Telegram-Specific Scams
    telegram_matches = 0
    for pattern in TELEGRAM_SPECIFIC_SCAMS:
        if re.search(pattern, text_lower):
            telegram_matches += 1
    if telegram_matches > 0:
        points += min(45, 35 * telegram_matches)
        reasons.append("Telegram scam signatures detected: Seed phrase harvesting, fake admin extortion, or prepaid task funnel")
        categories.append("Telegram Cyber Fraud")

    rule_score = min(100, points)

    return {
        "rule_score": rule_score,
        "reasons": reasons,
        "categories": list(set(categories))
    }

