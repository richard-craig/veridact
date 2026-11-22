# The known-assistant attester. Built from the repository root (it needs verify/ for JOSE):
#   docker build -f attester/Dockerfile -t veridact-attester .
# or straight from GitHub, as the Valet demo does:
#   docker build -f attester/Dockerfile https://github.com/veridactlabs/veridact.git#main
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY verify/ verify/
COPY attester/ attester/
RUN pip install ./verify \
 && pip install --no-deps ./attester \
 && useradd --uid 10001 --create-home veridact && mkdir -p /data && chown veridact /data
USER veridact
ENV VERIDACT_DATA=/data PORT=8100
EXPOSE 8100
CMD ["veridact-attester", "serve"]
