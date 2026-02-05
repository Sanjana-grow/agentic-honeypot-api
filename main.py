from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
import os
import re
import requests

app = FastAPI()

# 🔐 API Key (set in Render dashboard as environment variable)
API_KEY = os.getenv("API_KEY")

# 🧠 In-memory session storage
sessions = {}

# -----------------------------
# 📦 Request Models
# -----------------------------
class Message(BaseModel):
    sender: str
    text: str
    timestamp: int  # epoch ms

class HistoryMessage(BaseModel):
    sender: str
    text: str
    timestamp: int

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
    background_tasks: BackgroundTasks,
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

    # 📝 Store incoming message
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

    # 🤖 Agent reply
    if sessions[session_id]["scamDetected"]:
        reply = "Why is my account being blocked? Can you explain clearly?"
    else:
        reply = "Sorry, I didn’t understand. Can you please explain?"

    # 📡 FINAL CALLBACK TO GUVI (run in background)
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

        def send_final_callback(payload):
            try:
                print("🚨 Sending final GUVI payload:")
                print(payload)
                requests.post(
                    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
                    json=payload,
                    timeout=5
                )
                sessions[session_id]["finalReported"] = True
            except Exception as e:
                print("❌ Callback failed:", e)

        # Add background task
        background_tasks.add_task(send_final_callback, payload)

    # ✅ Return API response immediately
    return {
        "status": "success",
        "reply": reply
    }
