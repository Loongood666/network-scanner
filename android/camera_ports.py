"""
Common network camera development & management ports.
These are well-known ports used by major IP camera / NVR / DVR vendors.
"""

CAMERA_PORT_PRESETS = {
    "Hikvision": {
        "ports": "80,554,8000,443,8080,8443",
        "note": "HTTP(80), RTSP(554), Server(8000)"
    },
    "Dahua": {
        "ports": "80,554,37777,443,8080",
        "note": "HTTP(80), RTSP(554), TCP(37777)"
    },
    "Uniview (UNV)": {
        "ports": "80,554,443,8080",
        "note": "HTTP(80), RTSP(554)"
    },
    "Tiandy": {
        "ports": "80,554,8080,8000,8554",
        "note": "HTTP(80), RTSP(554/8554)"
    },
    "Xiongmai / Topsee": {
        "ports": "80,554,34567,8080,8554",
        "note": "HTTP(80), RTSP(554), CMS(34567)"
    },
    "Axis": {
        "ports": "80,554,443,8080",
        "note": "HTTP(80), RTSP(554)"
    },
    "Bosch": {
        "ports": "80,554,443,8080",
        "note": "HTTP(80), RTSP(554)"
    },
    "Samsung / Hanwha": {
        "ports": "80,554,443,8080,4520,4524",
        "note": "HTTP(80), RTSP(554), Admin(4520..4524)"
    },
    "Sony": {
        "ports": "80,554,443,8080",
        "note": "HTTP(80), RTSP(554)"
    },
    "Generic ONVIF": {
        "ports": "80,554,443,8080,8443,8000,8899,3702",
        "note": "HTTP, RTSP, ONVIF discovery(3702)"
    },
    "All Common Camera Ports": {
        "ports": "80,443,554,1935,3702,4520,4524,5540,7070,8000,8080,8081,8090,8443,8554,8888,8899,10080,34567,37777,50070",
        "note": "Combined common ports across vendors"
    }
}

# Default credentials for camera/nvr devices
DEFAULT_CAMERA_CREDS = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "1234567"),
    ("admin", "12345678"),
    ("admin", "123456789"),
    ("admin", "password"),
    ("admin", "888888"),
    ("admin", "666666"),
    ("admin", "pass"),
    ("admin", ""),
    ("admin", "admin123"),
    ("admin", "Admin123"),
    ("admin", "123abc"),
    ("admin", "hik12345"),
    ("admin", "dahua12345"),
    ("root", "root"),
    ("root", "admin"),
    ("root", "12345"),
    ("root", "password"),
    ("root", "pass"),
    ("root", "vizxv"),
    ("root", "xc3511"),
    ("root", "jvbzd"),
    ("root", "hi3518"),
    ("root", "anko"),
    ("root", "zlxx."),
    ("root", "system"),
    ("root", "0"),
    ("root", "realtek"),
    ("user", "user"),
    ("user", "12345"),
    ("user", "password"),
    ("guest", "guest"),
    ("guest", ""),
    ("service", "service"),
    ("supervisor", "supervisor"),
    ("ubnt", "ubnt"),
    ("hikvision", "hikvision"),
    ("default", "default"),
]