import json
import os
import re
import secrets
from pathlib import Path


class SecretStore:
    def __init__(self, directory: Path):
        self.directory = directory

    def path(self, reference: str):
        if not re.fullmatch(r"[a-f0-9]{32}", reference):
            raise ValueError("Invalid secret reference")
        return self.directory / reference

    def put(self, value: dict):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        reference = secrets.token_hex(16)
        with os.fdopen(
            os.open(self.path(reference), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
            "w",
            encoding="utf-8",
        ) as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        return reference

    def get(self, reference: str):
        return json.loads(self.path(reference).read_text(encoding="utf-8"))

    def delete(self, reference: str):
        self.path(reference).unlink(missing_ok=True)
