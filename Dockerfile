FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY static/ static/
RUN useradd --system --uid 10001 --create-home myvectors && mkdir /data && chown 10001:10001 /data
USER 10001
EXPOSE 42002
CMD ["gunicorn", "--bind", "0.0.0.0:42002", "--workers", "2", "--timeout", "90", "app:app"]
