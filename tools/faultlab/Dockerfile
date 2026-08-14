FROM python:3.12-slim
WORKDIR /app
COPY server.py /app/server.py
EXPOSE 18080 18081 18082/udp 18083 18053/udp
CMD ["python", "-u", "/app/server.py"]
