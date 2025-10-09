FROM python:3.12.3-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY argus.py /app/
COPY modules /app/modules
COPY utils /app/utils
COPY config /app/config

CMD ["python", "argus.py"]
