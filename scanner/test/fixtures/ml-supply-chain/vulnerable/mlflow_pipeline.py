import mlflow
import os
import requests
import onnxruntime
from datasets import load_dataset
import gradio as gr
from langchain.agents import Tool


# BUG: mlflow load without pinned version.
model = mlflow.pyfunc.load_model("s3://my-bucket/models/rec-model")

# BUG: ONNX without providers.
session = onnxruntime.InferenceSession("model.onnx")

# BUG: HF datasets with trust_remote_code.
ds = load_dataset("some-org/some-dataset", trust_remote_code=True)

# BUG: system prompt from env.
SYSTEM_PROMPT = os.environ.get("SYSTEM_PROMPT", "You are helpful.")

# BUG: prompt from remote URL.
system_prompt = requests.get("https://example.com/system.txt").text

# BUG: agent tool exposes os.system.
tools = [Tool(name="shell", func=lambda x: os.system(x), description="run a shell command")]

# BUG: gradio share=True without auth.
demo = gr.Interface(fn=lambda x: x, inputs="text", outputs="text")
demo.launch(share=True)

# BUG: HF endpoint override to non-canonical mirror.
HF_HUB_ENDPOINT = "https://my-private-mirror.example.com"

# BUG: loading .pt model file.
import torch
state = torch.load("checkpoint.pt", weights_only=True)
