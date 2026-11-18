# One image for the Month 1 staging stack: veridact-issuer, vbot, veridact-sidecar and
# veridact-sandbox. Each compose service picks its command.
#   docker build -f deploy/Dockerfile -t veridact:dev .
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY verify/ verify/
COPY issuer/ issuer/
COPY vbot/ vbot/
COPY sidecar/ sidecar/
COPY sandbox/ sandbox/
RUN pip install ./verify './issuer[dns]' ./vbot ./sidecar ./sandbox \
 && useradd --uid 10001 --create-home veridact \
 && mkdir -p /data /vbot/publish && chown -R veridact /data /vbot

USER veridact
WORKDIR /home/veridact
