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

CHAT_MODEL     = "gpt-4"
RECORD_SEC     = 5         # seconds to record
SAMPLE_RATE    = 16000     # mic sample rate
LOG_PATH       = "session_log.json"
DETAILS_FILE   = "/Users/mustafaahmed/Downloads/personal_banking_details.md"
# ── END CONFIG ─────────────────────────────────────────────────────────────────

# Initialize clients
openai_client = OpenAI(api_key=OPENAI_KEY)
tts_client    = texttospeech.TextToSpeechClient()

# ── Load Personal Details ─────────────────────────────────────────────────────
def load_personal_details(path: str):
    """
    Parses a Markdown file with key: value pairs under headings and returns a dict.
    """
    details = {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                m = re.match(r"[-*]\s*(.+?):\s*(.+)", line)
                if not m:
                    continue

                key   = m.group(1).strip().lower().replace(' ', '_')
                raw   = m.group(2).strip()

                # strip out any non-digit/dot/minus (e.g. $, commas)
                cleaned = re.sub(r"[^\d\.\-]", "", raw)

                # if cleaned is a valid number, convert to float
                if re.match(r"^-?\d+(\.\d+)?$", cleaned):
                    details[key] = float(cleaned)
                else:
                    details[key] = raw

        return details

    except Exception as e:
        print(f"Error loading personal details: {e}")
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
def ask_llm(history, query):
    system_prompt = (
        "You are the personal banking assistant for Morgan J. Reynolds. "
        "Answer questions about balance, spending, account details, and general queries. "
        "Always address the user as Morgan J. Reynolds, be helpful, concise, and professional."
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
    # Load details
    details = load_personal_details(DETAILS_FILE)
    # Seed conversation history
    history = []

    # Welcome
    name = details.get('name', 'Morgan J. Reynolds')
    welcome = f"Hello {name}, how can I assist you with your banking today?"
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
            ans = ask_llm(history, text)

        print(ans)
        speak(ans)
        history.append((text, ans))

    goodbye = f"Goodbye {name}. Have a great day!"
    print(goodbye)
    speak(goodbye)
    # Log session
    with open(LOG_PATH, 'w', encoding='utf-8') as f:
        json.dump([{'user':u,'assistant':a,'timestamp':datetime.now().isoformat()} for u,a in history], f, indent=2)

if __name__ == '__main__':
    main()
