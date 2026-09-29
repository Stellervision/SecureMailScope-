import os

from dotenv import load_dotenv

load_dotenv()
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.domain import (
    router as domain_router,
)
from app.api.eml import (
    router as eml_router,
)
from app.api.send import (
    router as send_router,
)
from app.api.mailbox import (
    router as mailbox_router,
)
from app.api.crypto import (
    router as crypto_router,
)
from app.api.ai import (
    router as ai_router,
)


app = FastAPI(
    title="SecureMailScope",
    description=(
        "AI-Assisted Cryptographic Security "
        "Posture Assessment for Secure Email "
        "Communications"
    ),
    version="0.1.0",
)


_cors_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# Extra origins for hosted deployments, e.g.
# SECUREMAILSCOPE_CORS_ORIGINS=https://securemailscope.netlify.app
_cors_extra = os.environ.get(
    "SECUREMAILSCOPE_CORS_ORIGINS",
    "",
)

for origin in _cors_extra.split(","):
    origin = origin.strip()

    if origin:
        _cors_origins.append(origin)


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(
    eml_router
)

app.include_router(
    domain_router
)

app.include_router(
    send_router
)

app.include_router(
    mailbox_router
)

app.include_router(
    crypto_router
)

app.include_router(
    ai_router
)


@app.get("/")
def root():
    return {
        "name": "SecureMailScope",
        "status": "online",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }