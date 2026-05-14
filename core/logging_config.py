import logging
import logging.handlers
import os
import pathlib

_LOG_DIR = pathlib.Path(__file__).parent.parent / "logs"
_LOG_DIR.mkdir(exist_ok=True)

_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

_FMT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"


def configure_logging() -> None:
    root = logging.getLogger()
    if root.handlers:
        return

    root.setLevel(_LOG_LEVEL)

    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(_FMT, _DATE_FMT))
    root.addHandler(console)

    rotating = logging.handlers.RotatingFileHandler(
        _LOG_DIR / "sentinelforge.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )
    rotating.setFormatter(logging.Formatter(_FMT, _DATE_FMT))
    root.addHandler(rotating)

    logging.getLogger("uvicorn.access").propagate = False
