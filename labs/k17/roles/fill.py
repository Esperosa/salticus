"""Zaplnění /data (porucha S15) bloky po 512 KiB, dokud nedojde místo."""
import os
i = 0
try:
    while True:
        with open(f"/data/fill-{i}", "wb") as f:
            f.write(b"\0" * 512 * 1024)
        i += 1
except OSError:
    pass
