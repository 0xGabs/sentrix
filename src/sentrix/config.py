# config.py
import os

# Rutas por defecto para los patrones
DEFAULT_PATTERN_PATHS = [
    os.path.join("patterns", "secrets.yaml")
]

# Archivos y rutas sensibles comunes (para escaneo rápido o modo watcher)
COMMON_SENSITIVE_PATHS = [
    ".env",
    ".git/config",
    ".git/HEAD",
    ".gitignore",
    "config.php",
    "phpinfo.php",
    "backup.zip",
    "id_rsa",
    "id_rsa.pub",
    "credentials.json",
    ".aws/credentials",
    "docker-compose.override.yml",
    ".npmrc",
    ".DS_Store",
    "secrets.json",
]

# Extensiones que vale la pena escanear
SCAN_EXTENSIONS = [
    ".py", ".js", ".env", ".json", ".yml", ".yaml",
    ".php", ".txt", ".ini", ".cfg", ".xml", ".properties"
]

# Severidad asociada a ciertos archivos clave
SENSITIVITY_MAP = {
    ".env": "high",
    ".git": "medium",
    ".git/config": "high",
    ".git/HEAD": "medium",
    "id_rsa": "critical",
    "id_rsa.pub": "low",
    "phpinfo.php": "critical",
    "backup.zip": "medium",
    "config.php": "high",
    "credentials.json": "critical",
    ".aws/credentials": "critical",
    "secrets.json": "high"
}

# Colores de severidad para la CLI (útil si quieres centralizar estilo)
SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "cyan"
}

