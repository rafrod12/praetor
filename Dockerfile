FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY praetor/ praetor/

# Non-root user.
RUN useradd --create-home praetor
USER praetor

EXPOSE 8088

ENV PRAETOR_NODE_COUNT=5 \
    PRAETOR_THRESHOLD=3

CMD ["python", "-m", "uvicorn", "praetor.server:app", "--host", "0.0.0.0", "--port", "8088"]
