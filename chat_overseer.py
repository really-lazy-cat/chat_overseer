# ══════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ══════════════════════════════════════════════════════════════════════════════

# WebSocket
import websocket
import ssl
import certifi
# HTTP
import requests
# Gmail
import base64
from email.mime.text import MIMEText
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
# Data
import json
import os
import re
import time
import threading
import logging
from logging.handlers import RotatingFileHandler
import pandas as pd
from datetime import datetime
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import Optional
from rapidfuzz import fuzz


# ══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════════════

formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

file_handler = RotatingFileHandler(
    filename="chat_overseer.log",
    maxBytes=5 * 1024 * 1024,
    backupCount=3
)
file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logging.basicConfig(
    level=logging.INFO,
    handlers=[file_handler, console_handler]
)


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

SOCKET_URL          = ""
LICENSE_ID          = 0
MESSENGER_TYPE      = "caWhatsApp"
CHATAPP_BASE_URL    = "https://api.chatapp.online"
CHATAPP_CREDS_FILE  = "sensitive_info/credentials/chatapp_request.json"
CHATAPP_TOKENS_FILE = "sensitive_info/credentials/chatapp_tokens.json"
BITRIX_WEBHOOK      = ""
GMAIL_SCOPES        = ["https://www.googleapis.com/auth/gmail.send"]
GMAIL_TOKEN_PATH    = "sensitive_info/credentials/email_token.json"
GMAIL_CREDS_PATH    = "sensitive_info/credentials/email.json"
NOTIFICATION_FROM   = ""
NOTIFICATION_TO     = ""
EMPLOYEE_LINKS_PATH = "sensitive_info/employee_links.csv"
LOG_DIR             = "sensitive_info/logs"

PAYMENT_DOMAINS = [
    "network.ae", "payfort.com", "checkout.com",
    "tap.company", "stripe.com", "paypal.com"
]

KEYWORDS = [
    # Identity & Personal Data
    "passport", "passport number", "emirates id", "emirates id number",
    "eid", "national id", "visa number", "residence visa", "uid",
    "unified number", "date of birth", "dob",
    # Vehicle & Motor
    "plate number", "plate no", "registration number", "reg number",
    "chassis number", "chassis no", "vin", "vehicle registration",
    "traffic file", "mulkiya",
    # Insurance — Policy
    "policy number", "policy no", "pol no", "cover note",
    "certificate number", "certificate of insurance", "coi",
    "endorsement number", "schedule", "premium", "deductible",
    "excess", "renewal", "expiry date", "sum insured",
    # Insurance — Claims
    "claim number", "claim no", "clm", "survey number", "repair order",
    "damage report", "accident report", "loss adjuster", "surveyor",
    "reimbursement", "claim amount", "settlement", "approved", "rejected",
    # Financial & Payment
    "aed", "payment", "transfer", "bank account", "account number",
    "iban", "card number", "credit card", "debit card", "cvv",
    "invoice number", "receipt", "premium amount", "outstanding",
    "balance due", "payment link", "cheque number", "pdc",
    # Medical & Health
    "member id", "medical card", "health card", "diagnosis",
    "prescription", "hospital", "clinic", "pre-authorization", "pre-auth",
    "lab result", "medical report", "treatment", "chronic",
    "insurance card", "network", "tpa",
    # Contact & Personal Information
    "mobile number", "phone number", "email address", "home address",
    "po box", "emirates post", "bank details", "salary",
    "date of joining", "employee id", "staff id",
    # Transaction & Reference Numbers
    "request number", "ref no", "reference number", "transaction id",
    "quote number", "application number", "file number", "case number",
    "ticket number",
    # High-Risk Phrases
    "send me your", "please share your", "can you send", "attach",
    "screenshot", "copy of", "scan of", "photo of your",
    "image of", "forward", "resend", "processed",
]

REGEX_PATTERNS = {
    "UAE Mobile Number": r"\+?971\s?5[0-9]\s?\d{3}\s?\d{4}",
    "Emirates ID":       r"784-\d{4}-\d{7}-\d{1}",
    "IBAN":              r"AE\d{2}\s?\d{3}\s?\d{16}",
    "Email Address":     r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "UAE Plate Number":  r"(?i)(plate|reg|mulkiya|registration)[\s\S]{0,20}[A-Z]{1,2}\s?\d{1,5}",
}

FUZZY_THRESHOLD = 85


# ══════════════════════════════════════════════════════════════════════════════
# MESSAGE CONTEXT — data carrier passed through the whole pipeline
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MessageContext:
    message_id:     str
    chat_id:        str
    side:           str         # "in" | "out"
    event_timestamp: int
    has_file:       bool
    text:           Optional[str]
    name:           str
    phone:          str
    license_id:     int
    messenger_type: str
    lead_id:        Optional[int]   = None
    employee_name:  str             = ""
    employee_email: str             = ""
    flag_reasons:   list            = field(default_factory=list)

    @classmethod
    def from_raw(cls, payload: dict, license_id: int, messenger_type: str) -> "MessageContext":
        msg         = payload
        from_user   = msg.get("fromUser", {})
        phone_raw   = from_user.get("phone", "")
        return cls(
            message_id      = msg.get("id"),
            chat_id         = msg.get("chat", {}).get("id"),
            side            = msg.get("side"),
            event_timestamp = msg.get("time"),
            has_file        = msg.get("message", {}).get("file") is not None,
            text            = msg.get("message", {}).get("text"),
            name            = from_user.get("name"),
            phone           = "+" + phone_raw if phone_raw else "",
            license_id      = license_id,
            messenger_type  = messenger_type,
        )


# ══════════════════════════════════════════════════════════════════════════════
# FACADE 1 — ChatApp API
# ══════════════════════════════════════════════════════════════════════════════

class ChatAppClient:
    def __init__(self):
        self.base_url       = CHATAPP_BASE_URL
        self.creds_file     = CHATAPP_CREDS_FILE
        self.tokens_file    = CHATAPP_TOKENS_FILE
        self.access_token:  Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_end_time: Optional[int] = None
        self._email = self._password = self._app_id = None

    # ── Credentials ───────────────────────────────────────────────────────────

    def load_credentials(self) -> bool:
        if os.path.exists(self.creds_file):
            with open(self.creds_file) as f:
                data = json.load(f)
            self._email    = data["email"]
            self._password = data["password"]
            self._app_id   = data["appId"]
            logging.info("ChatApp credentials loaded.")
            return True
        return False

    def save_credentials(self, email: str, password: str, app_id: str) -> None:
        self._email = email; self._password = password; self._app_id = app_id
        os.makedirs(os.path.dirname(self.creds_file), exist_ok=True)
        with open(self.creds_file, "w") as f:
            json.dump({"email": email, "password": password, "appId": app_id}, f)
        logging.info("ChatApp credentials saved.")

    def prompt_credentials(self) -> None:
        print("ChatApp credentials not found. Please enter them below:")
        self.save_credentials(
            email    = input("Email: ").strip(),
            password = input("Password: ").strip(),
            app_id   = input("App ID: ").strip(),
        )

    # ── Tokens ────────────────────────────────────────────────────────────────

    def load_tokens(self) -> bool:
        if os.path.exists(self.tokens_file):
            with open(self.tokens_file) as f:
                data = json.load(f)
            self.access_token  = data["accessToken"]
            self.refresh_token = data["refreshToken"]
            self.token_end_time = data["accessTokenEndTime"]
            logging.info("Tokens loaded from file.")
            return True
        return False

    def _save_tokens(self, data: dict) -> None:
        self.access_token   = data["accessToken"]
        self.refresh_token  = data["refreshToken"]
        self.token_end_time = data["accessTokenEndTime"]
        os.makedirs(os.path.dirname(self.tokens_file), exist_ok=True)
        with open(self.tokens_file, "w") as f:
            json.dump({
                "accessToken":        data["accessToken"],
                "refreshToken":       data["refreshToken"],
                "accessTokenEndTime": data["accessTokenEndTime"],
                "refreshTokenEndTime":data["refreshTokenEndTime"],
            }, f)
        logging.info("Tokens saved.")

    def fetch_new_tokens(self) -> bool:
        response = requests.post(
            f"{self.base_url}/v1/tokens",
            headers={"Content-Type": "application/json"},
            json={"email": self._email, "password": self._password, "appId": self._app_id}
        )
        if response.ok:
            self._save_tokens(response.json()["data"])
            logging.info("New tokens fetched.")
            return True
        logging.error(f"Failed to fetch tokens: {response.status_code} — {response.text}")
        return False

    def refresh_tokens(self) -> bool:
        response = requests.post(
            f"{self.base_url}/v1/tokens/refresh",
            headers={"Content-Type": "application/json"},
            json={"refreshToken": self.refresh_token}
        )
        if response.ok:
            self._save_tokens(response.json()["data"])
            logging.info("Tokens refreshed.")
            return True
        elif response.status_code == 403:
            logging.warning("Refresh token expired — fetching new tokens...")
            return self.fetch_new_tokens()
        logging.error(f"Failed to refresh tokens: {response.status_code} — {response.text}")
        return False

    def ensure_tokens(self) -> bool:
        if not self.load_tokens():
            logging.info("No saved tokens — fetching new ones...")
            return self.fetch_new_tokens()
        return True

    # ── API Calls ─────────────────────────────────────────────────────────────

    def authenticate_channel(self, socket_id: str, channel_name: str) -> Optional[str]:
        response = requests.post(
            f"{self.base_url}/broadcasting/auth",
            headers={"Authorization": self.access_token, "Content-Type": "application/json"},
            json={"socket_id": socket_id, "channel_name": channel_name}
        )
        if response.ok:
            return response.json().get("auth")
        logging.error(f"Channel auth failed: {response.status_code} — {response.text}")
        return None

    def send_warning(self, license_id: int, messenger_type: str, chat_id: str, text: str) -> tuple[bool, str]:
        url = f"{self.base_url}/v1/licenses/{license_id}/messengers/{messenger_type}/chats/{chat_id}/messages/text"
        try:
            response = requests.post(
                url,
                headers={"Authorization": self.access_token, "Content-Type": "application/json"},
                json={"text": text}
            )
            if response.ok:
                time_sent = time.strftime("%Y-%m-%d %H:%M:%S")
                logging.info(f"Warning sent to chat {chat_id}.")
                return True, time_sent
            logging.error(f"Failed to send warning: {response.status_code} — {response.text}")
            return False, ""
        except requests.RequestException as e:
            logging.error(f"Network error sending warning: {e}")
            return False, ""


# ══════════════════════════════════════════════════════════════════════════════
# FACADE 2 — Bitrix API
# ══════════════════════════════════════════════════════════════════════════════

class BitrixClient:
    def __init__(self, webhook: str):
        self.webhook = webhook

    def get_lead_info(self, client_num: str) -> tuple[Optional[int], str, str]:
        """Returns (lead_id, employee_name, employee_email) for a client phone number."""
        try:
            response = requests.post(
                url=f"{self.webhook}/crm.item.list",
                json={
                    "entityTypeId": 1,
                    "select": ["ID", "ASSIGNED_BY_ID"],
                    "filter": {"phone": client_num}
                }
            )
            items = response.json().get("result", {}).get("items", [])
            if not items:
                logging.info(f"No lead found for {client_num}")
                return None, "", ""

            lead_id        = items[0].get("id")
            assigned_by_id = items[0].get("assignedById")

            emp = requests.post(
                url=f"{self.webhook}/user.get",
                json={"filter": {"ID": assigned_by_id}, "select": ["NAME", "LAST_NAME", "EMAIL"]}
            )
            users = emp.json().get("result", [])
            if not users:
                return lead_id, "", ""

            u = users[0]
            return lead_id, f"{u.get('NAME')} {u.get('LAST_NAME')}", u.get("EMAIL", "")

        except Exception as e:
            logging.error(f"Error getting lead info: {e}")
            return None, "", ""

    def get_employee_link(self, employee_name: str) -> str:
        try:
            df = pd.read_csv(EMPLOYEE_LINKS_PATH)
            match = df[df.iloc[:, 0] == employee_name]
            if match.empty:
                return ""
            return match.iloc[0, 1]
        except Exception as e:
            logging.error(f"Error getting employee link: {e}")
            return ""

    def delete_file_messages(self, lead_id: int, event_timestamp: int) -> bool:
            """Fetch chat, then messages, and delete any with files after event_timestamp using sequential requests."""
            try:
                # Get the chat ID for the lead
                chat_response = requests.post(
                    url=f"{self.webhook}/imopenlines.crm.chat.get",
                    json={
                        "CRM_ENTITY_TYPE": "lead",
                        "CRM_ENTITY": lead_id,
                        "ACTIVE_ONLY": "N"
                    }
                )
                chat_response.raise_for_status()
                chats = chat_response.json().get("result", [])
                
                if not chats:
                    logging.info(f"No chat found for lead {lead_id}")
                    return False
                
                # Safely grab the CHAT_ID from the first chat object
                chat_id = chats[0].get("CHAT_ID")
                if not chat_id:
                    logging.info(f"Chat data structure malformed for lead {lead_id}")
                    return False

                # Get the messages using the dialog ID format "chat{CHAT_ID}"
                messages_response = requests.post(
                    url=f"{self.webhook}/im.dialog.messages.get",
                    json={
                        "DIALOG_ID": f"chat{chat_id}",
                        "LIMIT": 20
                    }
                )
                messages_response.raise_for_status()
                messages = messages_response.json().get("result", {}).get("messages", [])
                
                if not messages:
                    logging.info(f"No messages found in chat {chat_id}")
                    return False

                # Process and delete messages containing files
                deleted_any = False
                for message in messages:
                    if not message.get("params", {}).get("FILE_ID"):
                        continue
                    
                    msg_time = datetime.fromisoformat(message.get("date")).timestamp()
                    if msg_time < event_timestamp - 10:
                        continue
                    
                    msg_id = message.get("id")
                    r = requests.post(
                        url=f"{self.webhook}/im.message.delete",
                        json={"MESSAGE_ID": msg_id}
                    )
                    
                    if r.ok:
                        logging.info(f"Deleted Bitrix message {msg_id}.")
                        deleted_any = True
                    else:
                        logging.error(f"Failed to delete Bitrix message {msg_id}: {r.text}")
                        
                return deleted_any

            except Exception as e:
                logging.error(f"Error deleting Bitrix file messages: {e}")
                return False

# ══════════════════════════════════════════════════════════════════════════════
# FACADE 3 — Gmail
# ══════════════════════════════════════════════════════════════════════════════

class GmailClient:
    def __init__(self):
        self._service = None

    def _authenticate(self) -> None:
        creds = None
        if os.path.exists(GMAIL_TOKEN_PATH):
            creds = Credentials.from_authorized_user_file(GMAIL_TOKEN_PATH, GMAIL_SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(GMAIL_CREDS_PATH, GMAIL_SCOPES)
                creds = flow.run_local_server(port=0)
            with open(GMAIL_TOKEN_PATH, "w") as f:
                f.write(creds.to_json())
        self._service = build("gmail", "v1", credentials=creds)

    @property
    def service(self) -> None:
        if not self._service:
            self._authenticate()
        return self._service

    def send_notification(self, ctx: MessageContext, has_attachment: bool = False,
                          reasons: Optional[list] = None) -> bool:
        try:
            side_label = "Client" if ctx.side == "in" else "Employee"
            now        = time.strftime("%Y-%m-%d %H:%M:%S")

            if has_attachment:
                subject = f"File Sharing Violation Detected | {ctx.employee_name}"
                body    = f"""
A message with an attachment was detected.

Details:
- Sent by:               {ctx.name} | {side_label}
- Phone:                 {ctx.phone}
- Handled by:            {ctx.employee_name}
- Chat ID:               {ctx.chat_id}
- Message ID:            {ctx.message_id}
- Messenger:             {ctx.messenger_type}
- Time:                  {now}
"""
            else:
                reasons_text = "\n".join(f"  - {r}" for r in (reasons or []))
                subject      = "Message Flagged"
                body         = f"""
A message has been flagged for the following reasons:
{reasons_text}

Details:
- Sent by:               {ctx.name} | {side_label}
- Phone:                 {ctx.phone}
- Handled by:            {ctx.employee_name}
- Chat ID:               {ctx.chat_id}
- Message ID:            {ctx.message_id}
- Messenger:             {ctx.messenger_type}
- Time:                  {now}
"""

            msg             = MIMEText(body)
            msg["to"]       = NOTIFICATION_TO
            msg["from"]     = NOTIFICATION_FROM
            msg["subject"]  = subject
            encoded         = base64.urlsafe_b64encode(msg.as_bytes()).decode()
            result          = self.service.users().messages().send(
                userId="me", body={"raw": encoded}
            ).execute()
            logging.info(f"Notification sent. Gmail ID: {result['id']}")
            return True

        except Exception as e:
            logging.error(f"Failed to send notification: {e}")
            return False


# ══════════════════════════════════════════════════════════════════════════════
# CHAIN OF RESPONSIBILITY — message checking pipeline
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CheckResult:
    flagged:  bool
    reasons:  list
    is_file:  bool


class MessageHandler(ABC):
    def __init__(self):
        self._next: Optional["MessageHandler"] = None

    def set_next(self, handler: "MessageHandler") -> "MessageHandler":
        self._next = handler
        return handler

    def handle(self, ctx: MessageContext) -> Optional[CheckResult]:
        if self._next:
            return self._next.handle(ctx)
        return None


class FileHandler(MessageHandler):
    """Flags messages that contain a file attachment."""
    def handle(self, ctx: MessageContext) -> Optional[CheckResult]:
        if ctx.has_file:
            return CheckResult(flagged=True, reasons=["File attachment detected"], is_file=True)
        return super().handle(ctx)


class KeywordHandler(MessageHandler):
    """Flags messages containing exact keyword matches."""
    def handle(self, ctx: MessageContext) -> Optional[CheckResult]:
        if not ctx.text:
            return super().handle(ctx)

        text_lower = ctx.text.lower().strip()
        found      = [
            f"Keyword: '{kw}'"
            for kw in KEYWORDS
            if kw.lower() in text_lower
        ]

        if found:
            return CheckResult(flagged=True, reasons=found, is_file=False)

        # Fuzzy fallback only if no exact match
        words  = text_lower.split()
        fuzzy_found = []
        for kw in KEYWORDS:
            kw_words = kw.split()
            kw_count = len(kw_words)
            for i in range(len(words) - kw_count + 1):
                window = " ".join(words[i:i + kw_count])
                score  = fuzz.ratio(window, kw.lower())
                if score >= FUZZY_THRESHOLD:
                    fuzzy_found.append(f"Fuzzy Match: '{window}' ~ '{kw}' ({score:.0f}%)")
                    break

        if fuzzy_found:
            return CheckResult(flagged=True, reasons=fuzzy_found, is_file=False)

        return super().handle(ctx)


class RegexHandler(MessageHandler):
    """Flags messages matching UAE-specific regex patterns."""
    def handle(self, ctx: MessageContext) -> Optional[CheckResult]:
        if not ctx.text:
            return super().handle(ctx)

        found = [
            f"Pattern: {label}"
            for label, pattern in REGEX_PATTERNS.items()
            if re.search(pattern, ctx.text)
        ]

        if found:
            return CheckResult(flagged=True, reasons=found, is_file=False)
        return super().handle(ctx)


class URLHandler(MessageHandler):
    """Flags payment domain URLs and any unrecognised URLs."""
    def handle(self, ctx: MessageContext) -> Optional[CheckResult]:
        if not ctx.text:
            return super().handle(ctx)

        urls  = re.findall(r"https?://[^\s]+", ctx.text)
        found = []
        for url in urls:
            if any(domain in url for domain in PAYMENT_DOMAINS):
                found.append(f"Payment Link: {url}")
            else:
                found.append(f"URL detected: {url}")

        if found:
            return CheckResult(flagged=True, reasons=found, is_file=False)
        return super().handle(ctx)


def build_checking_chain() -> MessageHandler:
    """Constructs and returns the full handler chain."""
    file_handler    = FileHandler()
    keyword_handler = KeywordHandler()
    regex_handler   = RegexHandler()
    url_handler     = URLHandler()

    file_handler.set_next(keyword_handler)
    keyword_handler.set_next(regex_handler)
    regex_handler.set_next(url_handler)

    return file_handler


# ══════════════════════════════════════════════════════════════════════════════
# STRATEGY — action taken after flagging
# ══════════════════════════════════════════════════════════════════════════════

class ViolationStrategy(ABC):
    @abstractmethod
    def execute(self, ctx: MessageContext, result: CheckResult,
                chatapp: ChatAppClient, bitrix: BitrixClient, gmail: GmailClient):
        pass


class FileViolationStrategy(ViolationStrategy):
    """Handles file violations: warn, notify, delete from Bitrix, log to CSV."""

    def execute(self, 
                ctx: MessageContext, 
                result: CheckResult,
                chatapp: ChatAppClient, 
                bitrix: BitrixClient, 
                gmail: GmailClient
                ) -> None:

        warning_text = (
            f"As per CBUAE regulations, no personal information can be shared on this platform "
            f"including sharing files. Kindly delete the message. Please note that the message "
            f"should be deleted for everyone. For further communication, kindly contact "
            f"{ctx.employee_name} on the following platforms:"
            f" - Email: {ctx.employee_email}"
            f" - Chat: {ctx.employee_link}"
        )

        notification_sent           = gmail.send_notification(ctx, has_attachment=True)
        warning_sent, time_sent     = chatapp.send_warning(
            ctx.license_id, ctx.messenger_type, ctx.chat_id, warning_text
        )
        if ctx.lead_id:
            deleted = bitrix.delete_file_messages(ctx.lead_id, ctx.event_timestamp)

        if warning_sent:
            self._log(ctx, warning_sent, time_sent, notification_sent, deleted)

    def _log(
            self, 
            ctx: MessageContext, 
            warning_sent: bool,
            time_sent: str, 
            notification_sent: bool, 
            deleted: bool
            ) -> None:
        log = {
            "Sender's Name":         ctx.name if ctx.side == "in" else ctx.employee_name,
            "Sender's Number":       ctx.phone,
            "Handled By":            ctx.employee_name,
            "ChatID":                ctx.chat_id,
            "Warning Sent":          warning_sent,
            "Time Warning was Sent": time_sent if warning_sent else None,
            "Notification Sent":     notification_sent,
            "Deleted From Bitrix":   deleted,
            "Time Deleted" :         time.strftime("%Y-%m-%d %H:%M:%S") if deleted else None,
        }
        try:
            log_path = os.path.join(
                LOG_DIR,
                "incoming_log.csv" if ctx.side == "in" else "outgoing_log.csv"
            )
            os.makedirs(LOG_DIR, exist_ok=True)
            log_df = pd.DataFrame([log])
            if os.path.exists(log_path):
                old = pd.read_csv(log_path)
                pd.concat([old, log_df], ignore_index=True).to_csv(log_path, index=False)
            else:
                log_df.to_csv(log_path, mode='a', header=not os.path.exists(log_path), index=False)
        except Exception as e:
            logging.error(f"Couldn't log violation: {e}")


class TextViolationStrategy(ViolationStrategy):
    """Handles text violations: notify only."""

    def execute(self, ctx: MessageContext, result: CheckResult,
                chatapp: ChatAppClient, bitrix: BitrixClient, gmail: GmailClient):
        gmail.send_notification(ctx, has_attachment=False, reasons=result.reasons)


def resolve_strategy(result: CheckResult) -> ViolationStrategy:
    return FileViolationStrategy() if result.is_file else TextViolationStrategy()


# ══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class WebSocketManager:
    def __init__(self, chatapp: ChatAppClient, message_handler_fn):
        self.chatapp            = chatapp
        self.message_handler_fn = message_handler_fn
        self._ws: Optional[websocket.WebSocketApp] = None
        self._ssl_context       = ssl.create_default_context()
        self._ssl_context.load_verify_locations(certifi.where())
        self._lock              = threading.Lock()        
        self._reconnecting      = False                  

    def _send(self, ws, event: str, data=None) -> None:
        ws.send(json.dumps({"event": event, "data": data or {}}))

    def _ping_loop(self, ws) -> None:
        while True:
            time.sleep(25)
            try:
                if ws.sock and ws.sock.connected:
                    self._send(ws, "pusher:ping")
                    logging.debug("Sent pusher:ping")
                else:
                    break
            except Exception as e:
                logging.error(f"Failed to send ping: {e}")
                break

    def _on_open(self, ws) -> None:
        logging.info("WebSocket connection opened.")
        threading.Thread(target=self._ping_loop, args=(ws,), daemon=True).start()

    def _on_message(self, ws, message) -> None:
        try:
            payload = json.loads(message)
            event   = payload.get("event")
            data    = payload.get("data")

            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    pass

            if event == "pusher:connection_established":
                socket_id    = data.get("socket_id")
                channel_name = f"private-v1.licenses.{LICENSE_ID}.messengers.{MESSENGER_TYPE}"
                logging.info(f"Connected — socket_id={socket_id}")
                auth = self.chatapp.authenticate_channel(socket_id, channel_name)
                if auth:
                    self._send(ws, "pusher:subscribe", {"channel": channel_name, "auth": auth})

            elif event == "pusher_internal:subscription_succeeded":
                logging.info(f"Subscribed to channel: {payload.get('channel')}")

            elif event == "pusher:ping":
                self._send(ws, "pusher:pong")

            elif event == "message":
                self.message_handler_fn(json.dumps(data))

            elif event == "pusher:error":
                logging.error(f"Pusher error: {data}")

        except Exception as e:
            logging.error(f"Error in on_message: {e}")

    def _on_error(self, ws, error) -> None:
        logging.error(f"WebSocket error: {error}")

    def _on_close(self, ws, code, msg) -> None:
        logging.warning(f"WebSocket closed — code={code}. Reconnecting in 5 seconds...")
        time.sleep(5)
        self.reconnect()

    def start(self):
        with self._lock:
            self._ws = websocket.WebSocketApp(
                SOCKET_URL,
                on_open    = self._on_open,
                on_message = self._on_message,
                on_error   = self._on_error,
                on_close   = self._on_close,
            )
            threading.Thread(
                target=lambda: self._ws.run_forever(
                    ping_interval=25,
                    ping_timeout=10,
                    sslopt={"context": self._ssl_context}
                ),
                daemon=True
            ).start()
            logging.info("WebSocket thread started.")

    def reconnect(self) -> None:
        with self._lock:
            if self._reconnecting:
                logging.info("Reconnect already in progress, skipping.")
                return
            self._reconnecting = True

        logging.info("Reconnecting WebSocket...")
        try:
            self._ws.close()
        except Exception:
            pass
        time.sleep(2)
        self.start()

        with self._lock:
            self._reconnecting = False

    def close(self) -> None:
        if self._ws:
            self._ws.close()


# ══════════════════════════════════════════════════════════════════════════════
# TOKEN REFRESH LOOP
# ══════════════════════════════════════════════════════════════════════════════

def token_refresh_loop(chatapp: ChatAppClient, ws_manager: WebSocketManager) -> None:
    while True:
        time.sleep(1800)
        now            = int(time.time())
        time_remaining = chatapp.token_end_time - now
        logging.info(f"Token check — {time_remaining // 60} minutes remaining.")
        if time_remaining < 7200:
            logging.info("Token expiring soon — refreshing...")
            if chatapp.refresh_tokens():
                ws_manager.reconnect()


# ══════════════════════════════════════════════════════════════════════════════
# MESSAGE PIPELINE — ties everything together
# ══════════════════════════════════════════════════════════════════════════════

class MessagePipeline:
    def __init__(self, chatapp: ChatAppClient, bitrix: BitrixClient, gmail: GmailClient):
        self.chatapp  = chatapp
        self.bitrix   = bitrix
        self.gmail    = gmail
        self.chain    = build_checking_chain()

    def process(self, data: str) -> None:
        try:
            payload        = json.loads(data)
            inner          = payload.get("payload", {})
            meta           = inner.get("meta", {})
            messages       = inner.get("data", [])
            license_id     = meta.get("licenseId", LICENSE_ID)
            messenger_type = meta.get("messengerType", MESSENGER_TYPE)

            for raw_msg in messages:
                from_api = raw_msg.get("fromApi")
                text     = raw_msg.get("message", {}).get("text")

                if from_api:
                    continue

                ctx = MessageContext.from_raw(raw_msg, license_id, messenger_type)

                # Skip our own warning messages
                if text and "CBUAE regulations" in text:
                    continue

                # Enrich context with Bitrix data
                client_num = ctx.phone if ctx.side == "in" else "+" + ctx.chat_id
                ctx.lead_id, ctx.employee_name, ctx.employee_email = self.bitrix.get_lead_info(client_num)
                ctx.employee_link = self.bitrix.get_employee_link(ctx.employee_name)

                # Run through checking chain
                result = self.chain.handle(ctx)
                if not result or not result.flagged:
                    return

                logging.warning(f"Message flagged — reasons: {result.reasons}")

                # Execute the appropriate strategy
                strategy = resolve_strategy(result)
                strategy.execute(ctx, result, self.chatapp, self.bitrix, self.gmail)

        except Exception as e:
            logging.error(f"Error processing message: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    # Initialise facades
    chatapp = ChatAppClient()
    bitrix  = BitrixClient(webhook=BITRIX_WEBHOOK)
    gmail   = GmailClient()

    # ChatApp credentials
    if not chatapp.load_credentials():
        chatapp.prompt_credentials()

    # Tokens
    if not chatapp.ensure_tokens():
        logging.error("Could not obtain tokens. Exiting.")
        return

    # Message pipeline
    pipeline   = MessagePipeline(chatapp, bitrix, gmail)
    ws_manager = WebSocketManager(chatapp, pipeline.process)

    # Token refresh background thread
    threading.Thread(
        target=token_refresh_loop,
        args=(chatapp, ws_manager),
        daemon=True
    ).start()
    logging.info("Token refresh thread started.")

    # Start WebSocket
    ws_manager.start()
    logging.info("Listener started — monitoring for messages...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down...")
        ws_manager.close()


if __name__ == "__main__":
    main()