FROM python:3.12-slim
RUN apt-get update && apt-get install -y \
    traceroute \
    whois \
    nmap \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m argus
USER argus
WORKDIR /app
COPY . /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r Docker.requirements.txt
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["python", "argus.py"]