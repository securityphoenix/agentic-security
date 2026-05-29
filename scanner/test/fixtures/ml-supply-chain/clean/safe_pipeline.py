import mlflow
import onnxruntime
import gradio as gr

# Pinned model URI by version.
model = mlflow.pyfunc.load_model("models:/rec-model/3")

# ONNX with explicit providers.
session = onnxruntime.InferenceSession("model.onnx", providers=["CPUExecutionProvider"])

# System prompt baked into source.
SYSTEM_PROMPT = "You are a helpful assistant."

# Gradio launched with auth.
demo = gr.Interface(fn=lambda x: x, inputs="text", outputs="text")
demo.launch(share=True, auth=("user", "supersecret"))
