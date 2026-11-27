from fastapi import FastAPI

app = FastAPI(title="시스템 취약점 진단 API")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
