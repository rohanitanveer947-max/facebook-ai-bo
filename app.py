import os
# প্রক্সি সংক্রান্ত সমস্যা এড়াতে এটি যোগ করা হয়েছে
os.environ.pop('http_proxy', None)
os.environ.pop('https_proxy', None)

import hmac
import hashlib
import logging
import threading
import requests
from flask import Flask, request, jsonify
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

# ── কনফিগারেশন ──────────────────────────────────────────────
client       = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
ACCESS_TOKEN = os.getenv("FACEBOOK_PAGE_ACCESS_TOKEN")
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
APP_SECRET   = os.getenv("FACEBOOK_APP_SECRET")

SYSTEM_PROMPT = (
    "তুমি রোহানি তানভীরের এআই প্রতিনিধি। "
    "তুমি মার্জিত, বুদ্ধিদীপ্ত এবং সহযোগিতামূলক। "
    "সংক্ষিপ্ত ও সহায়ক উত্তর দাও।"
)

conversation_store: dict[str, list] = {}
store_lock = threading.Lock()
MAX_HISTORY = 10

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
)
logger = logging.getLogger(__name__)


def verify_facebook_signature(req) -> bool:
    if not APP_SECRET:
        logger.warning("APP_SECRET সেট নেই — signature যাচাই বন্ধ।")
        return True

    signature = req.headers.get("X-Hub-Signature-256", "")
    if not signature.startswith("sha256="):
        logger.warning("Signature হেডার নেই বা ফরম্যাট ভুল।")
        return False

    expected = hmac.new(
        APP_SECRET.encode("utf-8"),
        req.data,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(signature[7:], expected)


def get_ai_response(sender_id: str, user_input: str) -> str:
    with store_lock:
        history = conversation_store.setdefault(sender_id, [])
        history_snapshot = list(history)

    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + history_snapshot
    messages.append({"role": "user", "content": user_input})

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            max_tokens=512,
        )
        ai_reply = response.choices[0].message.content

        with store_lock:
            history = conversation_store.setdefault(sender_id, [])
            history.append({"role": "user",      "content": user_input})
            history.append({"role": "assistant", "content": ai_reply})
            if len(history) > MAX_HISTORY * 2:
                conversation_store[sender_id] = history[-(MAX_HISTORY * 2):]

        return ai_reply

    except Exception as e:
        logger.error(f"AI Error (sender={sender_id}): {e}")
        return "দুঃখিত, এই মুহূর্তে উত্তর দিতে পারছি না। একটু পরে আবার চেষ্টা করুন।"


def send_facebook_reply(comment_id: str, message: str) -> bool:
    url = f"https://graph.facebook.com/v20.0/{comment_id}/comments"
    try:
        resp = requests.post(
            url,
            params={"access_token": ACCESS_TOKEN},
            json={"message": message},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info(f"Reply sent → comment_id={comment_id}")
        return True
    except requests.HTTPError as e:
        logger.error(f"Facebook HTTP Error (comment={comment_id}): {e.response.status_code} — {e.response.text}")
        return False
    except requests.RequestException as e:
        logger.error(f"Facebook API Error (comment={comment_id}): {e}")
        return False


def process_comment(comment_id: str, sender_id: str, user_message: str):
    logger.info(f"Processing comment: id={comment_id}, sender={sender_id}")
    reply = get_ai_response(sender_id, user_message)
    success = send_facebook_reply(comment_id, reply)
    if not success:
        logger.warning(f"Reply পাঠানো যায়নি — comment_id={comment_id}")


@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    if request.method == "GET":
        mode      = request.args.get("hub.mode")
        token     = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == VERIFY_TOKEN:
            logger.info("Webhook verified ✓")
            return challenge, 200

        logger.warning(f"Webhook verification failed. mode={mode}, token={token}")
        return "Verification Failed", 403

    if not verify_facebook_signature(request):
        logger.warning("Invalid signature — request প্রত্যাখ্যান।")
        return jsonify({"error": "invalid signature"}), 403

    data = request.get_json(silent=True)
    if not data:
        logger.warning("Empty or invalid JSON body.")
        return jsonify({"error": "no data"}), 400

    logger.info(f"Received webhook payload: {data}")

    try:
        for entry in data.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})

                if value.get("verb") != "add":
                    continue

                comment_id   = value.get("comment_id")
                user_message = value.get("message", "").strip()
                sender_id    = value.get("from", {}).get("id") or comment_id

                if not comment_id or not user_message:
                    continue

                thread = threading.Thread(
                    target=process_comment,
                    args=(comment_id, sender_id, user_message),
                    daemon=True,
                )
                thread.start()
                logger.info(f"Thread started for comment_id={comment_id}")

    except Exception as e:
        logger.error(f"Webhook Processing Error: {e}", exc_info=True)

    return jsonify({"status": "ok"}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "running",
        "access_token_set": bool(ACCESS_TOKEN),
        "openai_key_set":   bool(os.getenv("OPENAI_API_KEY")),
    }), 200


if __name__ == "__main__":
    app.run(port=5000, debug=False)
