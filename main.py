from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Union
import os
import re
import requests

app = FastAPI()

# 🔐 API Key from environment variable (Render)
API_KEY = os.getenv("API_KEY", "123")  # fallback for testing

# 🧠 In-memory session storage
sessions = {}

# -----------------------------
# 📦 Request Models
# -----------------------------

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Union[int, str]  # ✅ Fix: allow both number & string

class HistoryMessage(BaseModel):
    sender: str
    text: str
    timestamp: Union[int, str]  # ✅ Fix

class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[HistoryMessage]] = []
    metadata: Optional[Metadata] = None

# -----------------------------
# 🚀 Honeypot Endpoint
# -----------------------------

@app.post("/honeypot")
def honeypot(
    data: HoneypotRequest,
    x_api_key: str = Header(None)
):
    # 🔐 API key validation
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    session_id = data.sessionId
    incoming_text = data.message.text.lower()

    # 🧠 Initialize session if new
    if session_id not in sessions:
        sessions[session_id] = {
            "messages": [],
            "scamDetected": False,
            "finalReported": False,
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

    # 🚨 Scam detection
    scam_keywords = [
        "blocked", "verify", "urgent", "account",
        "upi", "bank", "suspended", "click", "link"
    ]

    if not sessions[session_id]["scamDetected"]:
        for word in scam_keywords:
            if word in incoming_text:
                sessions[session_id]["scamDetected"] = True
                sessions[session_id]["intelligence"]["suspiciousKeywords"].append(word)

    # 🕵️ Intelligence extraction
    upi_matches = re.findall(r"\b[\w.\-]+@upi\b", data.message.text)
    url_matches = re.findall(r"https?://\S+", data.message.text)
    phone_matches = re.findall(r"\+91\d{10}", data.message.text)

    sessions[session_id]["intelligence"]["upiIds"].extend(upi_matches)
    sessions[session_id]["intelligence"]["phishingLinks"].extend(url_matches)
    sessions[session_id]["intelligence"]["phoneNumbers"].extend(phone_matches)

    # 🤖 Agent reply (human-like, non-revealing)
    if sessions[session_id]["scamDetected"]:
        reply = "Why is my account being blocked? Can you explain clearly?"
    else:
        reply = "Sorry, I didn’t understand. Can you please explain?"

    # 📡 FINAL CALLBACK TO GUVI (MANDATORY)
    if (
        sessions[session_id]["scamDetected"]
        and not sessions[session_id]["finalReported"]
        and len(sessions[session_id]["messages"]) >= 5
    ):
        payload = {
            "sessionId": session_id,
            "scamDetected": True,
            "totalMessagesExchanged": len(sessions[session_id]["messages"]),
            "extractedIntelligence": sessions[session_id]["intelligence"],
            "agentNotes": "Scammer used urgency and account suspension tactics"
        }

        # 🔍 Print for your visibility
        print("🚨 Sending final GUVI payload:")
        print(payload)

        try:
            requests.post(
                "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
                json=payload,
                timeout=5
            )
            sessions[session_id]["finalReported"] = True
        except Exception as e:
            print("❌ Callback failed:", e)

    # ✅ API response
    return {
        "status": "success",
        "reply": reply
    }
