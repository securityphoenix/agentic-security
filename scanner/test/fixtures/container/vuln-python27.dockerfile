FROM python:2.7
RUN pip install requests==2.20.0
COPY app.py /app.py
CMD ["python", "/app.py"]
