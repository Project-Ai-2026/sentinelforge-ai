import os
import pathlib

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import Base

_DATA_DIR = pathlib.Path(__file__).parent.parent / "data"
_DATA_DIR.mkdir(exist_ok=True)

_DB_URL = os.getenv("DATABASE_URL", f"sqlite:///{_DATA_DIR}/sentinelforge.db")

engine = create_engine(
    _DB_URL,
    connect_args={"check_same_thread": False},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
