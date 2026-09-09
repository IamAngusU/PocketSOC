from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Run the local PocketSOC workbench")
    result.add_argument("--host", default="127.0.0.1", help="Loopback host; remote exposure is intentionally rejected")
    result.add_argument("--port", type=int, default=8794)
    result.add_argument("--profile", choices=("desktop-lite", "desktop-full", "sensor", "server", "air-gapped", "developer"), default="desktop-lite")
    result.add_argument("--data-dir")
    result.add_argument("--datasets-dir")
    result.add_argument("--wireshark-dir")
    result.add_argument("--demo", action="store_true", help="Load harmless synthetic evidence into an isolated demo data directory")
    return result


def main() -> None:
    args = parser().parse_args()
    if args.host not in LOOPBACK_HOSTS:
        raise SystemExit("PocketSOC refuses non-loopback binding until authentication and TLS are implemented.")
    if not 1 <= args.port <= 65535:
        raise SystemExit("Port must be between 1 and 65535.")
    os.environ["POCKETSOC_HOST"] = args.host
    os.environ["POCKETSOC_PORT"] = str(args.port)
    os.environ["POCKETSOC_PROFILE"] = args.profile
    if args.demo:
        os.environ["POCKETSOC_DEMO"] = "1"
        if not args.data_dir and "POCKETSOC_DATA" not in os.environ:
            args.data_dir = str(Path(tempfile.gettempdir()) / "pocketsoc-demo")
    for name, value in (("POCKETSOC_DATA", args.data_dir), ("POCKETSOC_DATASETS", args.datasets_dir), ("POCKETSOC_WIRESHARK", args.wireshark_dir)):
        if value:
            os.environ[name] = value
    import uvicorn

    uvicorn.run("pocketsoc.main:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
