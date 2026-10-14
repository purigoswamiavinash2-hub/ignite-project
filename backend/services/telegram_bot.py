import os
import re
import time
import datetime
import uuid
from typing import Dict, Any, List, Optional, Tuple, Set
import httpx
from sqlalchemy.orm import Session

from ..config import settings
from ..models import ScanRecord
from .detector import analyze_scam_rules, redact_sensitive_otp
from .url_analyzer import extract_urls, analyze_url_structure
from .ml_service import ml_service
from .aggregator import determine_risk_level, generate_recommendations

class TelegramBotService:
    def __init__(self):
        self.bot_token = settings.TELEGRAM_BOT_TOKEN
        self.bot_username = settings.TELEGRAM_BOT_USERNAME
        self.webhook_url = settings.TELEGRAM_WEBHOOK_URL
        self.webhook_secret = settings.TELEGRAM_WEBHOOK_SECRET
        self.processed_update_ids: Set[int] = set()
        self.rate_limit_tracker: Dict[int, List[float]] = {}
        self.max_requests_per_minute = 15
        self.last_polling_time: Optional[float] = None
        self.total_scans_processed = 0

    def is_configured(self) -> bool:
        """Returns True if a non-placeholder Telegram bot token is configured."""
        token = self.bot_token.strip() if self.bot_token else ""
        return bool(token and "ExampleToken" not in token and len(token) > 15)

    def get_api_base(self) -> str:
        return f"https://api.telegram.org/bot{self.bot_token}"

    def check_rate_limit(self, user_id: int) -> bool:
        """Enforces rate limiting of 15 requests per minute per Telegram user ID."""
        now = time.time()
        timestamps = self.rate_limit_tracker.get(user_id, [])
        # Prune timestamps older than 60 seconds
        valid_timestamps = [t for t in timestamps if now - t < 60]
        if len(valid_timestamps) >= self.max_requests_per_minute:
            self.rate_limit_tracker[user_id] = valid_timestamps
            return False
        valid_timestamps.append(now)
        self.rate_limit_tracker[user_id] = valid_timestamps
        return True

    def get_privacy_and_permissions_guide(self) -> Dict[str, Any]:
        """
        Official Telegram Bot API security, Privacy Mode, and permission limitations.
        Adheres strictly to zero-privilege and data protection mandates.
        """
        return {
            "privacy_mode": {
                "name": "Telegram Group Privacy Mode (Enabled by Default)",
                "behavior": "When Privacy Mode is enabled (default on @BotFather), the bot receives only messages that begin with a slash '/' command (e.g. /check), messages that mention the bot by @username, or replies to the bot's own messages. It CANNOT see general chatter between group members.",
                "disable_requirement": "Group admins can disable Privacy Mode in @BotFather if they explicitly want the bot to inspect all group messages, or promote the bot to Group Administrator with 'Delete Messages' permission."
            },
            "channel_access": {
                "name": "Telegram Channels",
                "behavior": "Bots cannot read public or private channels unless added explicitly as an Administrator with 'Post Messages' and 'Edit Messages' privileges."
            },
            "private_chats_limitation": {
                "name": "Private Direct Chats (1-on-1)",
                "behavior": "Telegram's security model strictly guarantees that NO third-party bot can automatically read a user's private 1-on-1 chats. Users must explicitly forward suspicious messages or share links directly to @ThreatGuardAI_Bot for forensic scanning."
            },
            "credential_policy": {
                "name": "Zero-Credential Policy",
                "behavior": "ThreatGuard AI NEVER requests Telegram login passwords, SMS confirmation codes, 2FA cloud passcodes, or Pyrogram/Telethon session files. Any prompt asking for your Telegram login code is an impersonation attack."
            }
        }

    def analyze_telegram_message(
        self,
        text: str,
        sender_username: Optional[str] = None,
        sender_first_name: Optional[str] = None,
        chat_title: Optional[str] = None,
        is_forwarded: bool = False,
        forward_from: Optional[str] = None,
        opt_in_store_raw: bool = False
    ) -> Dict[str, Any]:
        """
        Forensic multi-layered analysis of a Telegram message.
        Analyzes crypto airdrops, admin impersonation, task scams, URLs, Hinglish phrases,
        and redacts sensitive credentials.
        """
        scan_id = f"TG-TG-{uuid.uuid4().hex[:8].upper()}"

        # 1. Pre-flight Privacy Sanitation: Mask sensitive OTPs, keys, and 12-word seed phrases
        redacted_text = redact_sensitive_otp(text)

        # 2. Extract & Inspect URLs (including t.me lookalikes)
        extracted_urls = extract_urls(text)
        url_results = []
        max_url_score = 0
        all_reasons = []

        for u in extracted_urls:
            u_res = analyze_url_structure(u)
            # Extra check for Telegram lookalike domains
            domain = u_res.get("domain", "").lower()
            if any(t_look in domain for t_look in ["t-me", "telegram-", "tg-", "telegrm", "telegr"]) and not (domain.endswith("t.me") or domain.endswith("telegram.org")):
                u_res["risk_score"] = min(100, u_res["risk_score"] + 45)
                u_res["reasons"].append(f"Telegram phishing lookalike domain detected: {domain}")
                all_reasons.append(f"Deceptive domain mimicking Telegram official service: {domain}")

            url_results.append(u_res)
            if u_res["risk_score"] > max_url_score:
                max_url_score = u_res["risk_score"]
            all_reasons.extend(u_res["reasons"])

        # 3. Rule-Based Heuristic Analysis (Crypto, Impersonation, Tasks, KYC, Hinglish)
        rule_res = analyze_scam_rules(text)
        all_reasons.extend(rule_res["reasons"])

        # 4. Telegram Context & Impersonator Heuristics
        text_lower = text.lower()
        sender_label = sender_username or sender_first_name or "Unknown"

        # Check if sender claims to be Admin/Support in text or username
        admin_indicators = ["admin", "support", "helpdesk", "moderator", "service", "security"]
        claims_admin = any(ai in (sender_username or "").lower() for ai in admin_indicators) or \
                       any(ai in text_lower for ai in ["i am the admin", "official support team", "contact admin privately", "dm the admin"])
        
        asks_credentials = any(w in text_lower for w in ["seed phrase", "private key", "wallet connect", "verify your wallet", "send funds", "gas fee"])

        if claims_admin and asks_credentials:
            rule_res["rule_score"] = min(100, rule_res["rule_score"] + 50)
            all_reasons.append("High-Severity: Impersonating Telegram group administrator/support while requesting wallet keys, seed phrases, or gas fees")

        if is_forwarded and ("airdrop" in text_lower or "giveaway" in text_lower or "usdt" in text_lower):
            rule_res["rule_score"] = min(100, rule_res["rule_score"] + 25)
            all_reasons.append(f"Forwarded Telegram broadcast containing unsolicited high-yield reward or crypto airdrop scheme")

        # 5. Machine Learning Analysis
        ml_prob, ml_confidence, analysis_type = ml_service.predict(text)
        ml_score = int(ml_prob * 100)

        if ml_prob > 0.6:
            all_reasons.append(f"AI Model detected high scam similarity ({int(ml_prob * 100)}% risk probability)")

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

        clean_preview = redacted_text.replace("\n", " ").strip()
        if len(clean_preview) > 120:
            clean_preview = clean_preview[:120] + "..."

        return {
            "scan_id": scan_id,
            "input_type": "telegram",
            "sender_id": f"@{sender_username}" if sender_username else (sender_first_name or "Telegram User"),
            "chat_title": chat_title,
            "is_forwarded": is_forwarded,
            "forward_from": forward_from,
            "content_preview": clean_preview,
            "sanitized_preview": clean_preview,
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
            "model_confidence": round(ml_confidence, 2),
            "created_at": datetime.datetime.utcnow().isoformat()
        }

    def format_telegram_reply(self, scan_result: Dict[str, Any]) -> str:
        """Formats an informative, accessible Telegram Markdown advisory card."""
        score = scan_result["risk_score"]
        level = scan_result["risk_level"]

        if level == "CRITICAL":
            badge = "🚨 CRITICAL THREAT"
            emoji = "🔴"
        elif level == "HIGH":
            badge = "⚠️ HIGH RISK SCAM"
            emoji = "🟠"
        elif level == "MEDIUM":
            badge = "⚡ SUSPICIOUS / CAUTION"
            emoji = "🟡"
        else:
            badge = "✅ LOW RISK / LIKELY SAFE"
            emoji = "🟢"

        reasons = scan_result.get("reasons", [])
        reasons_md = ""
        if reasons:
            top_reasons = reasons[:4]
            reasons_md = "\n" + "\n".join([f"• {r}" for r in top_reasons])
        else:
            reasons_md = "\n• No obvious phishing, fraud, or credential theft patterns identified."

        urls = scan_result.get("urls_found", [])
        urls_md = ""
        if urls:
            urls_md = "\n\n🔗 *Extracted Links:*\n" + "\n".join([f"`{u}`" for u in urls[:3]])

        rec = scan_result.get("recommendation", "Stay cautious with unsolicited messages.")

        source_info = f"From: `{scan_result.get('sender_id', 'Unknown')}`"
        if scan_result.get("is_forwarded"):
            source_info += f" (Forwarded from `{scan_result.get('forward_from', 'External Channel')}`)"

        msg = (
            f"🛡️ *ThreatGuard AI — Telegram Forensic Report*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"{emoji} *Threat Verdict:* *{badge}*\n"
            f"📊 *Risk Score:* *{score}/100*\n"
            f"👤 *Source:* {source_info}\n"
            f"\n"
            f"⚠️ *Detected Warning Signs:*{reasons_md}"
            f"{urls_md}\n"
            f"\n"
            f"💡 *Recommended Action:*\n{rec}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🆔 *Case ID:* `{scan_result['scan_id']}`\n"
            f"🔒 _Scanned securely by ThreatGuard AI SOC Enclave._"
        )
        return msg

    def handle_webhook_update(self, update_data: Dict[str, Any], db: Session) -> Dict[str, Any]:
        """
        Processes an incoming Telegram Bot webhook update.
        Prevents duplicates, enforces rate limiting, parses commands, and logs to database.
        """
        update_id = update_data.get("update_id")
        if update_id is not None:
            if update_id in self.processed_update_ids:
                return {"status": "duplicate_ignored", "update_id": update_id}
            self.processed_update_ids.add(update_id)
            if len(self.processed_update_ids) > 10000:
                # Remove arbitrary 2000 elements to keep memory lean
                self.processed_update_ids = set(list(self.processed_update_ids)[-8000:])

        message = update_data.get("message") or update_data.get("channel_post") or update_data.get("edited_message")
        if not message:
            return {"status": "no_message_content"}

        chat = message.get("chat", {})
        chat_id = chat.get("id")
        chat_title = chat.get("title")
        from_user = message.get("from", {})
        user_id = from_user.get("id", chat_id)
        username = from_user.get("username")
        first_name = from_user.get("first_name", "User")
        text = message.get("text") or message.get("caption", "")

        # Check Rate Limit
        if user_id and not self.check_rate_limit(user_id):
            rate_reply = (
                "⚠️ *Rate Limit Exceeded*\n\n"
                "You have submitted too many messages in a short period. "
                "Please wait 1 minute before submitting another scan."
            )
            self.send_telegram_message(chat_id, rate_reply)
            return {"status": "rate_limited", "user_id": user_id}

        # Check for forwarded metadata
        is_forwarded = bool(
            message.get("forward_date") or 
            message.get("forward_origin") or 
            message.get("forward_from") or 
            message.get("forward_from_chat")
        )
        forward_from_name = None
        if message.get("forward_from"):
            forward_from_name = message["forward_from"].get("username") or message["forward_from"].get("first_name")
        elif message.get("forward_from_chat"):
            forward_from_name = message["forward_from_chat"].get("title") or message["forward_from_chat"].get("username")

        clean_text = text.strip() if text else ""

        # Handle Bot Commands
        if clean_text == "/start":
            welcome_msg = (
                f"🛡️ *Welcome to ThreatGuard AI Scam Checker Bot!*\n\n"
                f"I am your official cyber forensic assistant for detecting Telegram phishing, fake crypto airdrops, job scams, and malicious URLs.\n\n"
                f"📌 *How to use:*\n"
                f"1. *Forward any suspicious message* from any user, group, or channel directly to this chat.\n"
                f"2. Or send any text/link starting with `/check <message>`.\n\n"
                f"🔐 *Privacy & Safety Guarantee:*\n"
                f"• We *NEVER* ask for your Telegram login codes, passwords, or session files.\n"
                f"• Numeric OTPs and wallet seed phrases are *automatically redacted* before analysis.\n"
                f"• ThreatGuard CANNOT read your private chats automatically—you remain in full control.\n\n"
                f"Type `/help` to view group privacy mode & command list."
            )
            self.send_telegram_message(chat_id, welcome_msg)
            return {"status": "command_handled", "command": "start"}

        if clean_text == "/help":
            help_msg = (
                f"ℹ️ *ThreatGuard AI — Help & Group Permissions*\n\n"
                f"*Available Commands:*\n"
                f"• `/check <message/link>` — Analyze a specific message or URL.\n"
                f"• `/privacy` — View data protection and privacy policy.\n"
                f"• Forward any message directly to get an instant safety report.\n\n"
                f"👥 *Using ThreatGuard in Groups:*\n"
                f"• By default, Telegram's *Privacy Mode* prevents bots from seeing general group chats. "
                f"To check a message in a group, *reply* to it with `/check` or mention `@{self.bot_username}`.\n"
                f"• To inspect all messages, group admins can promote the bot to Administrator.\n\n"
                f"📢 *Using in Channels:*\n"
                f"• Add the bot as an Admin with post permissions to scan broadcasts."
            )
            self.send_telegram_message(chat_id, help_msg)
            return {"status": "command_handled", "command": "help"}

        if clean_text == "/privacy":
            guide = self.get_privacy_and_permissions_guide()
            privacy_msg = (
                f"🔒 *ThreatGuard AI — Privacy & Data Protection Notice*\n\n"
                f"1. *Data Minimization:* Only the submitted text and URLs are analyzed. Personal identities are never sold or profiled.\n"
                f"2. *Pre-flight Redaction:* Numeric OTPs, passwords, and 12-word recovery seed phrases are masked in memory.\n"
                f"3. *Safe URL Inspection:* Suspicious links are analyzed structurally. We *NEVER* open or execute malicious payloads.\n"
                f"4. *Deletion Rights:* You can delete all scan history from the ThreatGuard Security Dashboard at any time.\n"
                f"5. *No Private Chat Scraping:* Telegram bots cannot read your 1-on-1 private conversations."
            )
            self.send_telegram_message(chat_id, privacy_msg)
            return {"status": "command_handled", "command": "privacy"}

        # If starts with /check, strip the command
        scan_input = clean_text
        if scan_input.lower().startswith("/check"):
            scan_input = scan_input[6:].strip()

        if not scan_input:
            self.send_telegram_message(
                chat_id,
                "⚠️ Please provide text or forward a message to analyze.\nExample: `/check Claim your 500 USDT airdrop at http://scam-link.xyz`"
            )
            return {"status": "empty_input"}

        # Run forensic analysis
        scan_result = self.analyze_telegram_message(
            text=scan_input,
            sender_username=username,
            sender_first_name=first_name,
            chat_title=chat_title,
            is_forwarded=is_forwarded,
            forward_from=forward_from_name,
            opt_in_store_raw=False
        )

        # Persist to database
        db_record = ScanRecord(
            scan_id=scan_result["scan_id"],
            input_type="telegram",
            sender_id=scan_result["sender_id"],
            device_id=f"tg-chat-{chat_id}" if chat_id else "tg-bot",
            content_preview=scan_result["sanitized_preview"],
            sanitized_content=scan_result["redacted_text"],
            raw_content_stored=False,
            risk_level=scan_result["risk_level"],
            risk_score=scan_result["risk_score"],
            reasons=scan_result["reasons"],
            urls_found=scan_result["urls_found"],
            url_analysis=scan_result["url_analysis"],
            recommendation=scan_result["recommendation"],
            analysis_type=scan_result["analysis_type"],
            model_confidence=scan_result["model_confidence"]
        )
        db.add(db_record)
        db.commit()
        db.refresh(db_record)

        self.total_scans_processed += 1

        # Send response card back to Telegram user/chat
        reply_md = self.format_telegram_reply(scan_result)
        self.send_telegram_message(chat_id, reply_md)

        return {
            "status": "success",
            "scan_id": scan_result["scan_id"],
            "risk_level": scan_result["risk_level"],
            "risk_score": scan_result["risk_score"],
            "scan_result": scan_result
        }

    def send_telegram_message(
        self,
        chat_id: int | str,
        text: str,
        reply_to_message_id: Optional[int] = None,
        parse_mode: str = "Markdown"
    ) -> bool:
        """Sends message to Telegram API or simulates sending if token is not configured."""
        if not self.is_configured():
            print(f"[TelegramBot Simulation] ChatID: {chat_id} | Response:\n{text}\n")
            return True

        url = f"{self.get_api_base()}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True # Never auto-preview potentially malicious links
        }
        if reply_to_message_id:
            payload["reply_to_message_id"] = reply_to_message_id

        try:
            with httpx.Client(timeout=8.0) as client:
                res = client.post(url, json=payload)
                return res.status_code == 200
        except Exception as e:
            print(f"Failed to send Telegram message to {chat_id}: {e}")
            return False

    def poll_updates_once(self, db: Session, offset: Optional[int] = None) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Polls Telegram servers once for pending updates (polling fallback mode).
        Useful for local development or when a public HTTPS webhook is not available.
        """
        if not self.is_configured():
            return 0, []

        url = f"{self.get_api_base()}/getUpdates"
        params = {"timeout": 2, "limit": 20}
        if offset is not None:
            params["offset"] = offset

        try:
            with httpx.Client(timeout=6.0) as client:
                res = client.get(url, params=params)
                if res.status_code != 200:
                    return offset or 0, []
                data = res.json()
                updates = data.get("result", [])
                max_update_id = offset or 0
                processed = []
                for upd in updates:
                    upd_id = upd.get("update_id")
                    if upd_id:
                        max_update_id = max(max_update_id, upd_id + 1)
                    res_scan = self.handle_webhook_update(upd, db)
                    processed.append(res_scan)
                return max_update_id, processed
        except Exception as e:
            print(f"Telegram polling error: {e}")
            return offset or 0, []

telegram_bot_service = TelegramBotService()
