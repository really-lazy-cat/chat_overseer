# Libraries for ChatApp connection
import pysher
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


logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s [%(levelname)s] %(message)s",
)


# Constants related to ChatApp's API
EMAIL = "harish@cosmosinsurance.com"
PASSWORD = "dd05aacf896eb1d751353321d9e34b7f"
APP_ID = "app_55017_1"
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
WARNING = "As per CBUAE regulations, file sharing is not permitted on this platform. Kindly delete the message with the attachment. Please note that the message should be deleted for everyone."

# Mail related details
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
NOTIFICATION_EMAIL = "ronakpunjabi2@gmail.com"  # email notifications are sent from
NOTIFICATION_EMAIL_TO = "ronakpunjabi2@gmail.com" # email notifications are sent to 


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
    """Refresh the token pair using the refreshToken. Used for ongoing renewal."""
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

def subscribe(pusher):
    channel_name = f"private-v1.licenses.{LICENSE_ID}.messengers.{MESSENGER_TYPE}"
    channel = pusher.subscribe(channel_name)
    channel.bind("message", handle_message)
    logging.info(f"Subscribed to {channel_name}")


def create_pusher():
    pusher = pysher.Pusher(
        key="ChatsAppApiProdKey",
        custom_host="socket.chatapp.online",
        port=6001,
        secure=True,
        auth_endpoint="https://api.chatapp.online/broadcasting/auth",
        auth_endpoint_headers={"Authorization": ACCESS_TOKEN}
    )
    pusher.connection.bind(
        "pusher:connection_established",
        lambda _: subscribe(pusher)
    )
    pusher.connection.bind(
        "pusher:connection_failed",
        lambda _: handle_disconnect()
    )
    return pusher


def handle_disconnect():
    logging.warning("WebSocket disconnected — reconnecting in 5 seconds...")
    time.sleep(5)
    reconnect_websocket()


def reconnect_websocket():
    global pusher_instance
    logging.info("Reconnecting WebSocket with new token...")
    try:
        pusher_instance.disconnect()
    except Exception:
        pass
    time.sleep(2)
    pusher_instance = create_pusher()
    pusher_instance.connect()
    logging.info("WebSocket reconnected.")

# GMAIL

def gmail_authenticate():
    creds = None
    token_path = "sensitive_info/token.json"
    cred_path = "sensitive_info/credentials.json"
    
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


def flag_text(text) -> bool:
    """
    Checks the text of the message for certain keywords and then returns a boolean value based on whether or not they are found.
    """
    keywords = [
        "Passport Number",      # to be continued...
        "Emirates ID",
        "EID",
        "Policy Number",
        "Claim Number",
        "Request Number",
    ]

    for keyword in keywords:
        if keyword.lower().strip() in text.lower().strip():
            return True
        else:
            return False


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
            time_sent = time.time()
            logging.info(f"Warning sent to chat {chat_id}.")
            return True, time_sent
        else:
            logging.info(f"Failed to send warning to chat {chat_id} : {response.status_code} - {response.text}")
            return False, 0.0
    except requests.RequestException as e:
        logging.error(f"Network error when sending warning to {chat_id} : {e}.")

def send_notification(chat_id, message_id, side, name, phone, messenger_type, has_attachment=False, text_flagged=False) -> bool:
    """
    Sends a notification through mail with the necessary details.
    """
    try:
        service = gmail_authenticate()

        # Build the email content
        sender = "ronakpunjabi2@gmail.com" # the gmail account you're sending from
        side_label = "Client" if side == "in" else "Employee"
        if has_attachment:
            subject = "File Sharing Violation Detected"
            body = f"""
A message with an attachment was detected and deleted.

Details:
- Sent by: {name} | {side_label}
- Phone: {phone}
- Chat ID: {chat_id}
- Message ID: {message_id}
- Messenger: {messenger_type}
- Time: {time.strftime("%Y-%m-%d %H:%M:%S")}
                    """

        elif text_flagged:
            subject = F"Message Flagged"
            body = f"""
A message has been flagged for having certain keywords.

Details:
- Sent by: {name} | {side_label}
- Phone: {phone}
- ChatID: {chat_id}
- Message ID: {message_id}
- Messenger: {messenger_type}
- Time: {time.strftime("%Y-%m-%d %H:%M:%S")}
                    """

        message = MIMEText(body)
        message["to"] = NOTIFICATION_EMAIL_TO
        message["from"] = sender
        message["subject"] = subject

        # Encode and send
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
            text = message.get("message", {}).get("text")
            from_user = message.get("fromUser", {})
            name = from_user.get("name")
            phone = from_user.get("phone")

            

            
            if not has_file:
                text_flagged = flag_text(text)
                print(f"TEXT FLAGGED: {text_flagged}")
                if text_flagged:
                    send_notification(chat_id, message_id, side, name, phone, messenger_type, has_file, text_flagged)
                    return
                else:
                    return          # if the text is not flagged, ignore it
            
            logging.warning(
                f"File detected - message id=({message_id}), "
                f"chat_id=({chat_id}), side={side}"
            )

            # Send a warning message back to whoever sent the file along with a
            # notification to a mail id.
            notification_sent = send_notification(chat_id, message_id, side, name, phone, messenger_type, has_file)
            warning_sent, time_sent = send_warning(license_id, messenger_type, chat_id, WARNING)

            if warning_sent:
                log = {
                    "Sender's Name": name,
                    "Sender's Number": phone,
                    "ChatID": chat_id,
                    "Warning Sent": warning_sent,
                    "Time Warning was Sent": time_sent if warning_sent else None,
                    "Notification Sent": notification_sent,
                }

                try:
                    log_path = "sensitive_info/logs.csv"
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
    pusher_instance = create_pusher()
    pusher_instance.connect()
    logging.info("Listener started — monitoring for file messages...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down...")
        pusher_instance.disconnect()


if __name__ == "__main__":
    main()
