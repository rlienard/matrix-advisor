FROM python:3.12-slim
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn>=0.30"
WORKDIR /sim
COPY ise_sim.py .
EXPOSE 9060
CMD ["uvicorn", "ise_sim:app", "--host", "0.0.0.0", "--port", "9060"]
