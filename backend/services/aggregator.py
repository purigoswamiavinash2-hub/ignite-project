from typing import Dict, Any, List, Optional
import uuid

from .url_analyzer import analyze_url_structure, extract_urls
from .detector import analyze_scam_rules, redact_sensitive_otp
from .ml_service import ml_service

def sanitize_content_preview(text: str, max_len: int = 120) -> str:
    cleaned = text.replace("\n", " ").strip()
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[:max_len] + "..."

def determine_risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    else:
        return "LOW"

def generate_recommendations(risk_level: str, reasons: List[str], has_urls: bool) -> str:
    if risk_level in ["CRITICAL", "HIGH"]:
        rec = "⚠️ DANGER: Do NOT click any links, download attachments, or provide sensitive information (OTPs, passwords, banking PINs). This message exhibits strong indicators of a phishing or fraud attempt."
        if has_urls:
            rec += " If you clicked a link, immediately change your account passwords and contact your official service provider."
        return rec
    elif risk_level == "MEDIUM":
        return "⚡ CAUTION: This message contains suspicious patterns or unverified links. Verify the identity of the sender through official channels before acting."
    else:
        return "✅ LOW RISK: No immediate phishing or scam indicators were detected. However, low risk is not proof of safety—always remain cautious with unsolicited messages."

def analyze_message_content(text: str) -> Dict[str, Any]:
    scan_id = f"TG-{uuid.uuid4().hex[:8].upper()}"

    # 1. Extract & Analyze URLs
    extracted_urls = extract_urls(text)
    url_results = []
    max_url_score = 0
    all_reasons = []

    for u in extracted_urls:
        u_res = analyze_url_structure(u)
        url_results.append(u_res)
        if u_res["risk_score"] > max_url_score:
            max_url_score = u_res["risk_score"]
        all_reasons.extend(u_res["reasons"])

    # 2. Rule-Based Scam Analysis
    rule_res = analyze_scam_rules(text)
    all_reasons.extend(rule_res["reasons"])

    # 3. Machine Learning Model Analysis
    ml_prob, ml_confidence, analysis_type = ml_service.predict(text)
    ml_score = int(ml_prob * 100)

    if ml_prob > 0.6:
        all_reasons.append(f"AI Language Model detected high scam similarity ({int(ml_prob * 100)}% risk probability)")

    # 4. Aggregated Score Calculation (Weighted)
    if extracted_urls:
        combined_score = int((ml_score * 0.4) + (rule_res["rule_score"] * 0.3) + (max_url_score * 0.3))
    else:
        combined_score = int((ml_score * 0.55) + (rule_res["rule_score"] * 0.45))

    # Safety Cap: If no rules triggered and no URLs present, cap score at 20 (LOW risk)
    if rule_res["rule_score"] == 0 and not extracted_urls:
        combined_score = min(combined_score, 20)

    final_score = min(100, max(0, combined_score))
    risk_level = determine_risk_level(final_score)
    unique_reasons = list(dict.fromkeys(all_reasons))

    recommendation = generate_recommendations(risk_level, unique_reasons, bool(extracted_urls))

    return {
        "scan_id": scan_id,
        "input_type": "message",
        "content_preview": sanitize_content_preview(text),
        "risk_level": risk_level,
        "risk_score": final_score,
        "reasons": unique_reasons,
        "urls_found": extracted_urls,
        "url_analysis": {
            "total_urls": len(extracted_urls),
            "max_url_score": max_url_score,
            "details": url_results
        } if url_results else None,
        "recommendation": recommendation,
        "analysis_type": analysis_type,
        "model_confidence": round(ml_confidence, 2)
    }

def analyze_single_url(url: str) -> Dict[str, Any]:
    scan_id = f"TG-URL-{uuid.uuid4().hex[:8].upper()}"
    u_res = analyze_url_structure(url)

    final_score = u_res["risk_score"]
    risk_level = determine_risk_level(final_score)
    recommendation = generate_recommendations(risk_level, u_res["reasons"], True)

    return {
        "scan_id": scan_id,
        "input_type": "url",
        "content_preview": sanitize_content_preview(url),
        "risk_level": risk_level,
        "risk_score": final_score,
        "reasons": u_res["reasons"],
        "urls_found": [url],
        "url_analysis": u_res,
        "recommendation": recommendation,
        "analysis_type": "Structural & Domain Feature Inspection",
        "model_confidence": 0.90
    }

def analyze_sms_message(
    text: str,
    sender_id: Optional[str] = None,
    opt_in_store_raw: bool = False,
    device_id: Optional[str] = None
) -> Dict[str, Any]:
    scan_id = f"TG-SMS-{uuid.uuid4().hex[:8].upper()}"

    # 1. Pre-flight Privacy Sanitation: Redact OTPs & secrets
    redacted_text = redact_sensitive_otp(text)

    # 2. Extract & Inspect URLs
    extracted_urls = extract_urls(text)
    url_results = []
    max_url_score = 0
    all_reasons = []

    for u in extracted_urls:
        u_res = analyze_url_structure(u)
        url_results.append(u_res)
        if u_res["risk_score"] > max_url_score:
            max_url_score = u_res["risk_score"]
        all_reasons.extend(u_res["reasons"])

    # 3. Rule-Based Heuristic Analysis (Indian SMS, KYC, Banking, Utilities, Hinglish)
    rule_res = analyze_scam_rules(text)
    all_reasons.extend(rule_res["reasons"])

    # 4. Check Sender ID Anomalies
    if sender_id:
        clean_sender = sender_id.strip()
        # If personal 10-digit number is pretending to send official bank/utility notices
        if clean_sender.startswith("+") or clean_sender.isdigit() or len(clean_sender) == 10:
            if rule_res["rule_score"] > 30:
                all_reasons.append(f"Suspicious Sender: Official banking/utility message sent from personal mobile number ({clean_sender}) instead of official alphanumeric sender ID")
                rule_res["rule_score"] = min(100, rule_res["rule_score"] + 20)

    # 5. Machine Learning Analysis
    ml_prob, ml_confidence, analysis_type = ml_service.predict(text)
    ml_score = int(ml_prob * 100)

    if ml_prob > 0.6:
        all_reasons.append(f"AI Language Model detected scam pattern similarity ({int(ml_prob * 100)}% risk probability)")

    # 6. Combined Risk Calculation
    if extracted_urls:
        base_score = int((ml_score * 0.30) + (rule_res["rule_score"] * 0.40) + (max_url_score * 0.30))
    else:
        base_score = int((ml_score * 0.35) + (rule_res["rule_score"] * 0.65))

    # Protect against ML false negative drag when strong heuristic rules or malicious URLs fire
    if rule_res["rule_score"] >= 50:
        combined_score = max(base_score, rule_res["rule_score"])
    elif max_url_score >= 50:
        combined_score = max(base_score, max_url_score)
    else:
        combined_score = base_score

    # Cap if completely benign
    if rule_res["rule_score"] == 0 and not extracted_urls:
        combined_score = min(combined_score, 15)

    final_score = min(100, max(0, combined_score))
    risk_level = determine_risk_level(final_score)
    unique_reasons = list(dict.fromkeys(all_reasons))
    recommendation = generate_recommendations(risk_level, unique_reasons, bool(extracted_urls))

    return {
        "scan_id": scan_id,
        "input_type": "sms",
        "sender_id": sender_id,
        "device_id": device_id,
        "content_preview": sanitize_content_preview(redacted_text),
        "sanitized_preview": sanitize_content_preview(redacted_text),
        "redacted_text": redacted_text,
        "raw_content_stored": opt_in_store_raw,
        "risk_level": risk_level,
        "risk_score": final_score,
        "reasons": unique_reasons,
        "urls_found": extracted_urls,
        "url_analysis": {
            "total_urls": len(extracted_urls),
            "max_url_score": max_url_score,
            "details": url_results
        } if url_results else None,
        "recommendation": recommendation,
        "analysis_type": analysis_type,
        "model_confidence": round(ml_confidence, 2)
    }
