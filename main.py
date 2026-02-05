from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import re

app = FastAPI()

# 🔐 API Key (change later if you want)
API_KEY = "MY_SECRET_KEY_123"

# 🧠 In-memory session storage
sessions = {}

# ---------- Input Models ----------

class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class HistoryMessage(BaseModel):
    sender: str
    text: str
    timestamp: str

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[HistoryMessage]
    metadata: Optional[dict]

# ---------- Routes ----------

@app.get("/")
def root():
    return {"message": "API is working"}

@app.post("/honeypot")
def honeypot(
    data: HoneypotRequest,
    x_api_key: str = Header(None)
):
    # 🔐 API key check
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    session_id = data.sessionId
    incoming_text = data.message.text.lower()

    # 🧠 Initialize session if new
    if session_id not in sessions:
        sessions[session_id] = {
            "messages": [],
            "scamDetected": False,
            "intelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            }
        }

    # 📝 Store message
    sessions[session_id]["messages"].append(data.message.text)

    # 🔍 Scam detection (simple & allowed)
    scam_keywords = [
        "blocked", "verify", "urgent", "account",
        "upi", "bank", "suspended", "click", "link"
    ]

    if not sessions[session_id]["scamDetected"]:
        if any(word in incoming_text for word in scam_keywords):
            sessions[session_id]["scamDetected"] = True
            sessions[session_id]["intelligence"]["suspiciousKeywords"].extend(
                [w for w in scam_keywords if w in incoming_text]
            )

    # 🧪 Intelligence extraction (regex-based, allowed)
    upi_matches = re.findall(r"\b[\w.-]+@upi\b", data.message.text)
    url_matches = re.findall(r"https?://\S+", data.message.text)
    phone_matches = re.findall(r"\+91\d{10}", data.message.text)

    sessions[session_id]["intelligence"]["upiIds"].extend(upi_matches)
    sessions[session_id]["intelligence"]["phishingLinks"].extend(url_matches)
    sessions[session_id]["intelligence"]["phoneNumbers"].extend(phone_matches)

    # 🤖 Agent behavior (simple but believable)
    if sessions[session_id]["scamDetected"]:
        reply = "Why is my account being blocked?"
    else:
        reply = "Sorry, I didn’t understand. Can you explain?"

    return {
        "status": "success",
        "reply": reply
    }
