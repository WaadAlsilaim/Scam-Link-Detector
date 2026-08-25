import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Optional

from predict import predict

app = FastAPI(
    title="Scam Link Detector API",
    description="Lexical + optional live-enrichment scam/phishing URL classifier.",
    version="0.1.0",
)

# Loosen for local dev / browser-extension use; tighten allow_origins in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).resolve().parent / "static"


class CheckRequest(BaseModel):
    url: str = Field(..., description="URL to check, e.g. 'http://paypa1-login.tk/verify'")
    use_enrichment: bool = Field(
        False, description="If true, also run live SSL/WHOIS/Safe-Browsing checks (slower)."
    )
    safe_browsing_api_key: Optional[str] = Field(
        None, description="Optional Google Safe Browsing API key, only used if use_enrichment=true."
    )


class CheckResponse(BaseModel):
    url: str
    lexical_score: float
    verdict: str
    top_signals: list[str]
    enrichment: Optional[dict] = None
    allowlisted: Optional[bool] = None


@app.get("/")
def root():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/check", response_model=CheckResponse)
def check_url(req: CheckRequest):
    result = predict(
        req.url,
        use_enrichment=req.use_enrichment,
        safe_browsing_api_key=req.safe_browsing_api_key,
    )
    return result


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
