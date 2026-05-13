# Libraries for ChatApp connection
import websocket
import ssl
import certifi
import requests
import json
import threading
# Libraries for Gmail connection
import os
import base64
from email.mime.text import MIMEText
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
# Libraries for logging
import time
import logging
import pandas as pd
# Regex
import re
from rapidfuzz import fuzz


logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s [%(levelname)s] %(message)s",
)


# Constants related to Websocket
SOCKET_URL = "wss://socket.chatapp.online:6001/app/ChatsAppApiProdKey?protocol=7&client=python&version=1.0"

ws_instance = None
ws_thread = None

# Constants related to ChatApp's API
CREDENTIALS_FILE = "sensitive_info/credentials/chatapp_request.json"
LICENSE_ID = 55570
MESSENGER_TYPE = "caWhatsApp"
BASE_URL = "https://api.chatapp.online"
TOKENS_FILE = "sensitive_info/chatapp_tokens.json"

# Tokens
ACCESS_TOKEN = None
REFRESH_TOKEN = None
ACCESS_TOKEN_END_TIME = None
pusher_instance = None

# Warning message to send to whoever sent the file.
WARNING = "As per CBUAE regulations, no personal information can be shared on this platform including sharing files. Kindly delete the message. Please note that the message should be deleted for everyone."

# Mail related details
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
NOTIFICATION_EMAIL = "shjops@cosmosinsurance.com"  # email notifications are sent from
NOTIFICATION_EMAIL_TO = "robin@cosmosinsurance.com" # email notifications are sent to 

# Payment domains to flag
PAYMENT_DOMAINS = [
    "network.ae", "payfort.com", "checkout.com", "tap.company",
    "stripe.com", "paypal.com"
]


# ChatApp Credentials

def load_chatapp_credentials():
    global EMAIL, PASSWORD, APP_ID
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            data = json.load(f)
        EMAIL = data["email"]
        PASSWORD = data["password"]
        APP_ID = data["appId"]
        logging.info("ChatApp credentials loaded.")
        return True
    return False

def save_chatapp_credentials(email, password, app_id):
    global EMAIL, PASSWORD, APP_ID
    EMAIL = email
    PASSWORD = password
    APP_ID = app_id
    os.makedirs(os.path.dirname(CREDENTIALS_FILE), exist_ok=True)
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump({"email": email, "password": password, "appId": app_id}, f)
    logging.info("ChatApp credentials saved.")

def prompt_and_save_chatapp_credentials():
    print("ChatApp credentials not found. Please enter them below:")
    email = input("Email: ")
    password = input("Password: ")
    app_id = input("App ID: ")
    save_chatapp_credentials(email, password, app_id)


# TOKENS

def save_tokens(access_token, refresh_token, access_token_end_time, refresh_token_end_time):
    global ACCESS_TOKEN, REFRESH_TOKEN, ACCESS_TOKEN_END_TIME
    ACCESS_TOKEN = access_token
    REFRESH_TOKEN = refresh_token
    ACCESS_TOKEN_END_TIME = access_token_end_time
    os.makedirs(os.path.dirname(TOKENS_FILE), exist_ok=True)
    with open(TOKENS_FILE, "w") as f:
        json.dump({
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "accessTokenEndTime": access_token_end_time,
            "refreshTokenEndTime": refresh_token_end_time
        }, f)
    logging.info("Tokens saved.")


def load_tokens():
    global ACCESS_TOKEN, REFRESH_TOKEN, ACCESS_TOKEN_END_TIME
    if os.path.exists(TOKENS_FILE):
        with open(TOKENS_FILE, "r") as f:
            data = json.load(f)
        ACCESS_TOKEN = data["accessToken"]
        REFRESH_TOKEN = data["refreshToken"]
        ACCESS_TOKEN_END_TIME = data["accessTokenEndTime"]
        logging.info("Tokens loaded from file.")
        return True
    return False


def fetch_new_tokens():
    """Get a brand new token pair using email/password. Used only on first run."""
    response = requests.post(
        f"{BASE_URL}/v1/tokens",
        headers={"Content-Type": "application/json"},
        json={"email": EMAIL, "password": PASSWORD, "appId": APP_ID}
    )
    if response.ok:
        data = response.json()["data"]
        save_tokens(
            data["accessToken"],
            data["refreshToken"],
            data["accessTokenEndTime"],
            data["refreshTokenEndTime"]
        )
        logging.info("New tokens fetched successfully.")
        return True
    else:
        logging.error(f"Failed to fetch new tokens: {response.status_code} — {response.text}")
        return False


def refresh_tokens():
    global REFRESH_TOKEN
    response = requests.post(
        f"{BASE_URL}/v1/tokens/refresh",
        headers={"Content-Type": "application/json"},
        json={"refreshToken": REFRESH_TOKEN}
    )
    if response.ok:
        data = response.json()["data"]
        save_tokens(
            data["accessToken"],
            data["refreshToken"],
            data["accessTokenEndTime"],
            data["refreshTokenEndTime"]
        )
        logging.info("Tokens refreshed successfully.")
        return True
    elif response.status_code == 403:
        logging.warning("Refresh token invalid or expired — fetching new tokens with credentials...")
        return fetch_new_tokens()
    else:
        logging.error(f"Failed to refresh tokens: {response.status_code} — {response.text}")
        return False


def token_refresh_loop():
    """
    Background thread that checks token expiry every 30 minutes.
    Refreshes proactively if less than 2 hours remain on the accessToken.
    Also triggers a WebSocket reconnect after refreshing.
    """
    while True:
        time.sleep(1800)  # check every 30 minutes
        now = int(time.time())
        time_remaining = ACCESS_TOKEN_END_TIME - now
        logging.info(f"Token check — {time_remaining // 60} minutes remaining.")

        if time_remaining < 7200:  # less than 2 hours left
            logging.info("Token expiring soon — refreshing...")
            if refresh_tokens():
                reconnect_websocket()



# WEBSOCKET / PUSHER

def send_ws(ws, event, data=None):
    payload = json.dumps({"event": event, "data": data or {}})
    ws.send(payload)


def authenticate_channel(ws, socket_id, channel_name):
    """Hit ChatApp's auth endpoint to get the auth signature for a private channel."""
    response = requests.post(
        "https://api.chatapp.online/broadcasting/auth",
        headers={
            "Authorization": ACCESS_TOKEN,
            "Content-Type": "application/json"
        },
        json={
            "socket_id": socket_id,
            "channel_name": channel_name
        }
    )
    if response.ok:
        return response.json().get("auth")
    else:
        logging.error(f"Channel auth failed: {response.status_code} — {response.text}")
        return None

def ping_loop(ws):
    """Send Pusher application-level pings every 25 seconds to keep the connection alive."""
    while True:
        time.sleep(25)
        try:
            send_ws(ws, "pusher:ping")
            logging.debug("Sent pusher:ping")
        except Exception as e:
            logging.error(f"Failed to send ping: {e}")
            break

def on_open(ws):
    logging.info("WebSocket connection opened.")
    # Start ping thread
    ping_thread = threading.Thread(target=ping_loop, args=(ws,), daemon=True)
    ping_thread.start()


def on_message(ws, message):
    try:
        payload = json.loads(message)
        event = payload.get("event")
        data = payload.get("data")

        # Parse nested data string if needed
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                pass

        if event == "pusher:connection_established":
            socket_id = data.get("socket_id")
            logging.info(f"Connected — socket_id={socket_id}")

            # Subscribe to private channel
            channel_name = f"private-v1.licenses.{LICENSE_ID}.messengers.{MESSENGER_TYPE}"
            auth = authenticate_channel(ws, socket_id, channel_name)
            if auth:
                send_ws(ws, "pusher:subscribe", {
                    "channel": channel_name,
                    "auth": auth
                })

        elif event == "pusher_internal:subscription_succeeded":
            logging.info(f"Subscribed to channel: {payload.get('channel')}")

        elif event == "pusher:ping":
            # Respond to server pings immediately
            send_ws(ws, "pusher:pong")
            logging.debug("Responded to ping.")

        elif event == "message":
            handle_message(json.dumps(data))

        elif event == "pusher:error":
            logging.error(f"Pusher error: {data}")

    except Exception as e:
        logging.error(f"Error in on_message: {e}")


def on_error(ws, error):
    logging.error(f"WebSocket error: {error}")


def on_close(ws, close_status_code, close_msg):
    logging.warning(f"WebSocket closed — code={close_status_code}, msg={close_msg}. Reconnecting in 5 seconds...")
    time.sleep(5)
    start_websocket()


def start_websocket():
    global ws_instance, ws_thread
    
    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations(certifi.where())
    
    ws_instance = websocket.WebSocketApp(
        SOCKET_URL,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    ws_thread = threading.Thread(
        target=lambda: ws_instance.run_forever(
            ping_interval=25,
            ping_timeout=10,
            sslopt={"context": ssl_context}
        ),
        daemon=True
    )
    ws_thread.start()
    logging.info("WebSocket thread started.")


def reconnect_websocket():
    global ws_instance
    logging.info("Reconnecting WebSocket with refreshed token...")
    try:
        ws_instance.close()
    except Exception:
        pass
    time.sleep(2)
    start_websocket()

# GMAIL

def gmail_authenticate():
    creds = None
    token_path = "sensitive_info/credentials/email_token.json"
    cred_path = "sensitive_info/credentials/email.json"
    
    # Load existing token if available
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    
    # If no valid credentials, authenticate
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(cred_path, SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Save token for future runs
        with open(token_path, "w") as token:
            token.write(creds.to_json())
    
    return build("gmail", "v1", credentials=creds)


def flag_text(text: str) -> tuple[bool, list[str]]:
    """
    Checks the text of the message for certain keywords and regex patterns.
    Returns a tuple of (flagged: bool, reasons: list of what was found).
    """
    if not text:
        return False, []

    found = []
    text_lower = text.lower().strip()

    # ── Keywords ──────────────────────────────────────────────────────────────
    keywords = [
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
        "image of", "forward", "resend",
    ]

    for keyword in keywords:
        if keyword.lower() in text_lower:
            found.append(f"Keyword: '{keyword}'")

    # ── Fuzzy Keyword Matching ────────────────────────────────────────────────
    if not found:  # only run fuzzy if exact matching found nothing
        FUZZY_THRESHOLD = 85
        words = text_lower.split()

        for keyword in keywords:
            keyword_word_count = len(keyword.split())
            for i in range(len(words) - keyword_word_count + 1):
                window = " ".join(words[i:i + keyword_word_count])
                score = fuzz.ratio(window, keyword.lower())
                if score >= FUZZY_THRESHOLD:
                    found.append(f"Fuzzy Match: '{window}' ~ '{keyword}' ({score:.0f}%)")
                    break


    # Implement fuzzy search.

    # ── Regex Patterns ────────────────────────────────────────────────────────
    patterns = {
        "UAE Mobile Number": r"\+?971\s?5[0-9]\s?\d{3}\s?\d{4}",
        "Emirates ID":       r"784-\d{4}-\d{7}-\d{1}",
        "IBAN":              r"AE\d{2}\s?\d{3}\s?\d{16}",
        "Email Address":     r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "UAE Plate Number":  r"(?i)(plate|reg|mulkiya|registration)[\s\S]{0,20}[A-Z]{1,2}\s?\d{1,5}",
    }

    for label, pattern in patterns.items():
        if re.search(pattern, text):
            found.append(f"Pattern: {label}")

    # ── Payment Links ─────────────────────────────────────────────────────────
    urls = re.findall(r"https?://[^\s]+", text)
    for url in urls:
        for domain in PAYMENT_DOMAINS:
            if domain in url:
                found.append(f"Payment Link: {url}")
                break
        else:
            # Flag any URL not on an approved list
            found.append(f"URL detected: {url}")

    if found:
        return True, found
    return False, []

def get_employee_name(client_num: str) -> str:
    BITRIX_WEBHOOK = ""
    try:
        response = requests.post(
            url=f"{BITRIX_WEBHOOK}/crm.contact.list",
            json={
                "select": ["ID", "NAME", "LAST_NAME", "ASSIGNED_BY_ID", "PHONE"],
                "filter": {
                    "PHONE": client_num
                }
            }
        )
        contacts = response.json().get("result", [])
        if not contacts:
            logging.info(f"No contact found for {client_num}")
            return ""
        
        assigned_by_id = contacts[0].get("ASSIGNED_BY_ID")
        logging.info(assigned_by_id)

        employee_response = requests.post(
            url=f"{BITRIX_WEBHOOK}/user.get",
            json={
                "filter": {"ID": assigned_by_id},
                "select": ["NAME", "LAST_NAME", "EMAIL"]
            }
        )
        users = employee_response.json().get("result", [])
        if not users:
            return ""
        
        user = users[0]
        return f"{user.get('NAME')} {user.get('LAST_NAME')}"

    except Exception as e:
        logging.error(f"Error getting employee name: {e}")
        return ""

def send_warning(license_id, messenger_type, chat_id, warning_text) -> tuple[bool, float]:
    """
    Sends a warning message to inform either that the message has been deleted, or that the message should be deleted.
    """
    url = f"{BASE_URL}/v1/licenses/{license_id}/messengers/{messenger_type}/chats/{chat_id}/messages/text"
    headers = {
        "Authorization" : ACCESS_TOKEN,
        "Content-Type" : "application/json",
    }
    payload = {"text" : warning_text}

    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.ok:
            time_sent = time.strftime("%Y-%m-%d %H:%M:%S")
            logging.info(f"Warning sent to chat {chat_id}.")
            return True, time_sent
        else:
            logging.info(f"Failed to send warning to chat {chat_id} : {response.status_code} - {response.text}")
            return False, 0.0
    except requests.RequestException as e:
        logging.error(f"Network error when sending warning to {chat_id} : {e}.")

def send_notification(chat_id, message_id, side, name, phone, messenger_type, employee_name="",
                      has_attachment=False, text_flagged=False, reasons=None) -> bool:
    """
    Sends a notification through mail with the necessary details.
    """
    try:
        service = gmail_authenticate()
        side_label = "Client" if side == "in" else "Employee"
        if has_attachment:
            subject = "File Sharing Violation Detected"
            body = f"""
A message with an attachment was detected.
Details:
- Sent by: {name} | {side_label}
- Phone: {phone}
- Handled by: {employee_name}
- Chat ID (Client's Number): {chat_id}
- Message ID: {message_id}
- Messenger: {messenger_type}
- Time: {time.strftime("%Y-%m-%d %H:%M:%S")}
            """
        elif text_flagged:
            subject = "Message Flagged"
            reasons_text = "\n".join(f"  - {r}" for r in (reasons or []))
            body = f"""
A message has been flagged for the following reasons:
{reasons_text}
Details:
- Sent by: {name} | {side_label}
- Phone: {phone}
- Handled by: {employee_name}
- Chat ID (Client's Number): {chat_id}
- Message ID: {message_id}
- Messenger: {messenger_type}
- Time: {time.strftime("%Y-%m-%d %H:%M:%S")}
            """
        message = MIMEText(body)
        message["to"] = NOTIFICATION_EMAIL_TO
        message["from"] = NOTIFICATION_EMAIL
        message["subject"] = subject
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        send_result = service.users().messages().send(
            userId="me",
            body={"raw": encoded_message}
        ).execute()
        logging.info(f"Notification email sent. Message ID: ({send_result['id']})")
        return True
    
    except Exception as e:
        logging.error(f"Failed to send notification email: {e}")
        return False

def handle_message(data):
    """
    Extracts the necessary details from any message sent or received, and handles what to do with it based on certain criteria.
    """
    try:
        payload = json.loads(data)
        inner = payload.get("payload", {})
        meta = inner.get("meta", {})
        messages = inner.get("data", [])

        license_id = meta.get("license_Id", LICENSE_ID)
        messenger_type = meta.get("messengerType", MESSENGER_TYPE)

        for message in messages:
            # Extract the needed information
            message_id = message.get("id")
            chat_id = message.get("chat", {}).get("id")
            side = message.get("side")
            has_file = message.get("message", {}).get("file") is not None
            from_api = message.get("fromApi")
            text = message.get("message", {}).get("text")
            if from_api or text == WARNING:
                continue
            from_user = message.get("fromUser", {})
            name = from_user.get("name")
            phone = "+" + from_user.get("phone")
            if side == "in":
                employee_name = get_employee_name(phone)
            elif side == "out":
                client_num = "+" + chat_id
                employee_name = get_employee_name(client_num)

            
            if not has_file:
                text_flagged, reasons = flag_text(text)
                if text_flagged:
                    logging.warning(f"Message flagged — reasons: {reasons}")
                    send_notification(
                        chat_id, message_id, side, name, phone,
                        messenger_type, employee_name, has_attachment=False,
                        text_flagged=True, reasons=reasons
                    )
                return
            
            logging.warning(
                f"File detected - message id=({message_id}), "
                f"chat_id=({chat_id}), side={side}"
            )

            # Send a warning message back to whoever sent the file along with a
            # notification to a mail id.
            notification_sent = send_notification(chat_id, message_id, side, name, phone, messenger_type, employee_name, has_file)
            warning_sent, time_sent = send_warning(license_id, messenger_type, chat_id, WARNING)

            if warning_sent:
                log = {
                    "Sender's Name": name if side == "in" else employee_name,
                    "Sender's Number": phone,
                    "Handled By" : employee_name,
                    "ChatID": chat_id,
                    "Warning Sent": warning_sent,
                    "Time Warning was Sent": time_sent if warning_sent else None,
                    "Notification Sent": notification_sent,
                }

                try:
                    log_path = "sensitive_info/logs/incoming_log.csv" if side == "in" else "sensitive_info/logs/outgoing_log.csv"
                    log = pd.DataFrame([log])
                    if os.path.exists(log_path):
                        old_log = pd.read_csv(log_path)
                        new_log = pd.concat([old_log, log], axis=0, ignore_index=True)
                        new_log.to_csv(log_path, index=False)
                    else:
                        log.to_csv(log_path, index=False)
                except Exception as e:
                    logging.error(f"Couldn't log message due to error: {e}")


    except Exception as e:
        logging.error(f"Error processing message event: {e}")



def main():
    global pusher_instance

    if not load_chatapp_credentials():
        prompt_and_save_chatapp_credentials()

    # Load or fetch tokens
    if not load_tokens():
        logging.info("No saved tokens found — fetching new ones...")
        if not fetch_new_tokens():
            logging.error("Could not obtain tokens. Exiting.")
            return

    # Start background token refresh thread
    refresh_thread = threading.Thread(target=token_refresh_loop, daemon=True)
    refresh_thread.start()
    logging.info("Token refresh thread started.")

    # Start WebSocket
    start_websocket()
    logging.info("Listener started — monitoring for file messages...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down...")
        if ws_instance:
            ws_instance.close()

if __name__ == "__main__":
    main()