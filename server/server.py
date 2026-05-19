"""
Secure Photo Backup Server.
Receives encrypted photo thumbnails from Android app, decrypts and stores them.
Requires: Python 3.9+, cryptography, fastapi, uvicorn
"""

import os
import io
import json
import uuid
import base64
import hashlib
import logging
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

# ---------------------------------------------------------------------------
# RSA Key Management (Server-Side)
# ---------------------------------------------------------------------------

KEY_DIR = Path("./keys")
KEY_DIR.mkdir(exist_ok=True)
PRIVATE_KEY_PATH = KEY_DIR / "backup_server_private_key.pem"
PUBLIC_KEY_PATH = KEY_DIR / "backup_server_public_key.pem"

app = FastAPI(title="Photo Backup Server")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("backup_server")

# Storage for received photos
STORAGE_DIR = Path("./received_photos")
STORAGE_DIR.mkdir(exist_ok=True)
THUMB_DIR = STORAGE_DIR / "thumbnails"
THUMB_DIR.mkdir(exist_ok=True)
META_DIR = STORAGE_DIR / "metadata"
META_DIR.mkdir(exist_ok=True)


def load_or_generate_keys():
    """Load existing RSA key pair or generate a new one."""
    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        logger.info("Loading existing RSA key pair...")
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None
            )
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        logger.info("Keys loaded successfully.")
    else:
        logger.info("Generating new RSA-2048 key pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        public_key = private_key.public_key()

        # Save private key
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save public key
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        logger.info("New key pair generated and saved.")

    return private_key, public_key


# Load or generate server keys
server_private_key, server_public_key = load_or_generate_keys()


def decrypt_transmission(encrypted_aes_key: bytes, encrypted_payload: bytes):
    """
    Decrypt incoming transmission from Android app:
    1. Decrypt AES session key using RSA private key
    2. Decrypt payload using AES-256-GCM
    Returns plaintext bytes
    """
    # Step 1: Decrypt AES session key
    session_key = server_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Step 2: Decrypt payload with AES-256-GCM
    aesgcm = AESGCM(session_key)
    nonce = encrypted_payload[:12]
    ciphertext = encrypted_payload[12:]

    associated_data = b""  # No AAD in current protocol
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)

    return plaintext


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    """Server health check."""
    return {
        "status": "online",
        "service": "photo_backup",
        "version": "1.0.0"
    }


@app.post("/api/upload")
async def upload_photo(
    metadata: str = Form(...),
    key: UploadFile = File(...),
    file: UploadFile = File(...),
):
    """
    Receive encrypted photo upload from Android app.
    multipart/form-data with fields: metadata, key, file
    """
    try:
        # Parse metadata
        meta = json.loads(metadata)
        filename = meta.get("filename", "unknown.jpg")
        file_hash = meta.get("file_hash", "")
        thumb_fmt = meta.get("thumbnail_format", "jpeg")

        logger.info(f"Receiving: {filename} (hash={file_hash[:16]}...)")

        # Read encrypted AES key
        encrypted_aes_key = await key.read()
        # Read encrypted payload
        encrypted_payload = await file.read()

        # Decrypt
        plaintext_data = decrypt_transmission(encrypted_aes_key, encrypted_payload)

        logger.info(f"Decrypted successfully: {len(plaintext_data)} bytes")

        # Save thumbnail
        file_id = str(uuid.uuid4())
        safe_filename = f"{file_id}.{thumb_fmt}"
        thumb_path = THUMB_DIR / safe_filename

        with open(thumb_path, "wb") as f:
            f.write(plaintext_data)

        # Save metadata
        meta_path = META_DIR / f"{file_id}.json"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    **meta,
                    "file_id": file_id,
                    "saved_path": str(thumb_path),
                    "received_at": meta.get("timestamp", ""),
                },
                f,
                indent=2,
            )

        # Update index
        index_path = STORAGE_DIR / "index.json"
        index = []
        if index_path.exists():
            with open(index_path, "r") as f:
                index = json.load(f)
        index.append(
            {
                "file_id": file_id,
                "filename": filename,
                "file_hash": file_hash,
                "saved_path": str(thumb_path),
                "received_at": meta.get("timestamp", ""),
            }
        )
        with open(index_path, "w") as f:
            json.dump(index, f, indent=2)

        return {
            "success": True,
            "file_id": file_id,
            "message": "Photo received and decrypted successfully",
        }

    except Exception as e:
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/photos")
async def list_photos():
    """List all backed up photos."""
    index_path = STORAGE_DIR / "index.json"
    if not index_path.exists():
        return {"photos": []}
    with open(index_path, "r") as f:
        return {"photos": json.load(f)}


@app.get("/api/stats")
async def get_stats():
    """Get backup statistics."""
    index_path = STORAGE_DIR / "index.json"
    if not index_path.exists():
        return {"total": 0, "total_size": 0}

    with open(index_path, "r") as f:
        photos = json.load(f)

    total_size = 0
    for p in photos:
        try:
            total_size += os.path.getsize(p.get("saved_path", ""))
        except OSError:
            pass

    return {
        "total": len(photos),
        "total_size_bytes": total_size,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
    }


@app.get("/thumbnail/{file_id}")
async def get_thumbnail(file_id: str):
    """Serve a thumbnail image."""
    for ext in ["jpeg", "jpg", "png", "raw"]:
        thumb_path = THUMB_DIR / f"{file_id}.{ext}"
        if thumb_path.exists():
            from fastapi.responses import FileResponse
            return FileResponse(thumb_path)
    raise HTTPException(status_code=404, detail="Thumbnail not found")


# ---------------------------------------------------------------------------
# Admin Dashboard
# ---------------------------------------------------------------------------

@app.get("/dashboard", response_class=JSONResponse)
async def dashboard(request: Request):
    """Simple dashboard showing backup status."""
    stats = await get_stats()
    photos = []
    index_path = STORAGE_DIR / "index.json"
    if index_path.exists():
        with open(index_path, "r") as f:
            photos = json.load(f)[-20:]  # Last 20

    html = f"""
    <html>
    <head><title>Photo Backup Dashboard</title></head>
    <body>
        <h1>Photo Backup Server</h1>
        <h2>Statistics</h2>
        <p>Total photos: {stats['total']}</p>
        <p>Total size: {stats['total_size_mb']} MB</p>
        <h2>Recent Backups (last 20)</h2>
        <ul>
            {''.join(f'<li>{p["filename"]} ({p["received_at"]})</li>' for p in photos)}
        </ul>
    </body>
    </html>
    """
    return HTMLResponse(content=html, status_code=200)


# ---------------------------------------------------------------------------
# Server Startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("Starting Photo Backup Server...")
    logger.info(f"Keys loaded from: {KEY_DIR}")
    logger.info(f"Storage directory: {STORAGE_DIR}")

    # Print public key for Android app configuration
    pub_key_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    logger.info("=" * 60)
    logger.info("COPY THIS PUBLIC KEY INTO android/crypto_utils.py:")
    logger.info("=" * 60)
    logger.info(pub_key_pem)
    logger.info("=" * 60)

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")