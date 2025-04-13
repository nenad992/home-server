# Dockerfile

FROM python:3.11-slim

WORKDIR /app

# Instalacija dependencija
RUN apt-get update && apt-get install -y iputils-ping

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Kopiraj ostatak koda
COPY . .

EXPOSE 8888

CMD ["python", "app.py"]
