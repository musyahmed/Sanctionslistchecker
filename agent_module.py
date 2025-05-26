#!/usr/bin/env python3
"""
Enhanced Interactive Voice-&-File-Enabled Personal Banking Agent for Morgan J. Reynolds:
 - Personal details loaded from a Markdown file
 - OpenAI Whisper-1 ASR (audio→text via API)
 - GPT-4 powered conversational intelligence
 - Google Cloud TTS for all responses
 - Fuzzy matching and clarification for ambiguous queries
 - Conversation logging to session_log.json
 - Always addresses user as Morgan J. Reynolds
"""

import os
import json
import tempfile
import subprocess
import re
from datetime import datetime

import sounddevice as sd
import soundfile as sf
import numpy as np
from openai import OpenAI
from google.cloud import texttospeech

# ── CONFIG ────────────────────────────────────────────────────────────────────
OPENAI_KEY    = os.getenv("OPENAI_API_KEY")
if not OPENAI_KEY:
    raise RuntimeError("Please set OPENAI_API_KEY")
# Ensure GOOGLE_APPLICATION_CREDENTIALS is set to service account JSON

CHAT_MODEL     = "gpt-4" # CHAT_MODEL could be set via an environment variable for more flexibility.
RECORD_SEC     = 5         # seconds to record
SAMPLE_RATE    = 16000     # mic sample rate
LOG_PATH       = "session_log.json"
VECTOR_DB_URI  = os.getenv("VECTOR_DB_URI", "mock_db")
# ── END CONFIG ─────────────────────────────────────────────────────────────────

# Initialize clients
openai_client = OpenAI(api_key=OPENAI_KEY)
tts_client    = texttospeech.TextToSpeechClient()
vector_db_client = None # Placeholder for actual vector database client; logic to use VECTOR_DB_URI would go here.

# ── Mock Vector DB Data and Accessor ───────────────────────────────────────────
mock_vector_db_data = {
    "user123": {
        "user_id": "user123",
        "name": "Morgan J. Reynolds",
        "current_balance": 25000.75,
        "account_type": "checking",
        "credit_score": 780,
        "address": "123 Main St, Anytown, USA",
        "phone_number": "555-123-4567",
        "email": "morgan.reynolds@example.com",
        "recent_transactions_embeddings": [0.1, 0.2, 0.3, 0.4, 0.5] 
    },
    "user456": {
        "user_id": "user456",
        "name": "Alex P. Keaton",
        "current_balance": 1500.00,
        "account_type": "savings",
        "credit_score": 720,
        "address": "456 Oak Ave, Anytown, USA",
        "phone_number": "555-987-6543",
        "email": "alex.keaton@example.com",
        "recent_transactions_embeddings": [0.6, 0.7, 0.8, 0.9, 1.0]
    }
}

def get_user_data_from_vector_db(user_id: str, db_client: any) -> dict:
    """
    Retrieves user data from the mock vector database or a real one based on VECTOR_DB_URI.
    In a real scenario, db_client would be initialized using VECTOR_DB_URI.
    """
    if VECTOR_DB_URI == "mock_db" or db_client is None:
        print(f"Using mock vector database. Fetching data for user_id '{user_id}'...")
        data = mock_vector_db_data.get(user_id, {})
        if data:
            print(f"Data found for user_id '{user_id}' in mock DB.")
        else:
            print(f"No data found for user_id '{user_id}' in mock DB.")
        return data
    else:
        # Placeholder for actual database client interaction using VECTOR_DB_URI
        print(f"Attempting to connect to real vector database at URI: {VECTOR_DB_URI} (Not implemented).")
        # print(f"Querying real vector database for user_id '{user_id}'...")
        # return db_client.get(user_id) # This would be the actual call
        print("Actual vector database client interaction not implemented yet.")
        return {}

# ── TTS Playback ────────────────────────────────────────────────────────────────
def speak(text: str):
    try:
        synthesis_input = texttospeech.SynthesisInput(text=text)
        voice = texttospeech.VoiceSelectionParams(
            language_code="en-US",
            ssml_gender=texttospeech.SsmlVoiceGender.FEMALE
        )
        audio_config = texttospeech.AudioConfig(audio_encoding=texttospeech.AudioEncoding.MP3)
        response = tts_client.synthesize_speech(
            input=synthesis_input, voice=voice, audio_config=audio_config
        )
        with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as out:
            out.write(response.audio_content)
            tmp_path = out.name
        subprocess.run(["afplay", tmp_path], check=False)
    except Exception as e:
        print(f"TTS Error: {e}")
        try:
            subprocess.run(["say", text], check=False)
        except:
            print("System TTS fallback failed.")

# ── ASR Helpers ────────────────────────────────────────────────────────────────
def transcribe_file(path: str) -> str:
    resp = openai_client.audio.transcriptions.create(
        model="whisper-1", file=open(path, "rb"), language="en", temperature=0.0
    )
    return resp.text


def record_audio(seconds=RECORD_SEC, sr=SAMPLE_RATE) -> str:
    print(f"Recording {seconds}s… please speak now.")
    audio = sd.rec(int(seconds*sr), samplerate=sr, channels=1, dtype="int16")
    sd.wait()
    tmp = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
    sf.write(tmp.name, audio, sr)
    return tmp.name

# ── Conversation & Q&A ─────────────────────────────────────────────────────────
def ask_llm(history, query, user_name: str, user_details: dict):
    context_from_db = "Based on your recent activity and account details: "
    if 'account_type' in user_details:
        context_from_db += f" Your account type is {user_details['account_type']}."
    if 'recent_transactions_embeddings' in user_details:
        context_from_db += " Information from your recent transaction embeddings has been considered."
    # (In a real scenario, this would be actual content from a vector search based on the query)

    system_prompt = (
        f"You are the personal banking assistant for {user_name}. "
        f"Answer questions about balance, spending, account details, and general queries. "
        f"Always address the user as {user_name}, be helpful, concise, and professional. "
        f"{context_from_db}"
    )
    messages = [{"role": "system", "content": system_prompt}]
    for ui, ai in history[-5:]:
        messages.append({"role": "user", "content": ui})
        messages.append({"role": "assistant", "content": ai})
    messages.append({"role": "user", "content": query})
    resp = openai_client.chat.completions.create(model=CHAT_MODEL, messages=messages)
    return resp.choices[0].message.content.strip()

# ── Main Loop ──────────────────────────────────────────────────────────────────
def main():
    # Prompt for User ID
    current_user_id = input("Please enter your User ID (e.g., 'user123', 'user456'): ").strip()

    # Load details using the provided User ID
    details = get_user_data_from_vector_db(current_user_id, vector_db_client)
    
    if not details:
        print("User ID not found. Exiting.")
        return

    # Seed conversation history
    history = []

    # Welcome
    user_name = details.get('name', 'Valued Customer') # Fallback name
    welcome = f"Hello {user_name}, how can I assist you with your banking today?"
    print(welcome)
    speak(welcome)
    history.append((welcome, ''))
    
    while True:
        print("\nOptions: 1) Audio File  2) Live Recording  3) Type  4) Quit")
        choice = input("Choice [1-4]: ").strip().lower()
        if choice in ('4','quit','exit'):
            break

        # Get query text
        if choice == '1':
            path = input("Audio file path: ").strip()
            if not os.path.isfile(path): continue
            text = transcribe_file(path)
        elif choice == '2':
            wav = record_audio()
            text = transcribe_file(wav)
        else:
            text = input("Your question: ").strip()
        if not text:
            continue

        # Answer
        if 'balance' in text.lower():
            bal = details.get('current_balance')
            if bal is not None:
                ans = f"Your current balance is ${bal:.2f}."
        else:
            ans = ask_llm(history, text, user_name, details)

        print(ans)
        speak(ans)
        history.append((text, ans))

    goodbye = f"Goodbye {user_name}. Have a great day!"
    print(goodbye)
    speak(goodbye)
    # Log session
    with open(LOG_PATH, 'w', encoding='utf-8') as f:
        json.dump([{'user':u,'assistant':a,'timestamp':datetime.now().isoformat()} for u,a in history], f, indent=2)

if __name__ == '__main__':
    main()
