"""POSITIVE: Python — Flask request.json flows into OpenAI prompt."""
from openai import OpenAI
from flask import request

client = OpenAI()

def chat():
    user_msg = request.json["text"]
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": f"Translate this: {user_msg}"},
        ],
    )
    return response
