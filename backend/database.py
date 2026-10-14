from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
import os
from .config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    from . import models  # Ensure models are registered with Base.metadata
    Base.metadata.create_all(bind=engine)

    # Auto-migrate SQLite columns if table already exists
    if settings.DATABASE_URL.startswith("sqlite"):
        with engine.connect() as conn:
            try:
                result = conn.execute(text("PRAGMA table_info(scan_history)")).fetchall()
                existing_cols = [row[1] for row in result]
                
                if "sender_id" not in existing_cols:
                    conn.execute(text("ALTER TABLE scan_history ADD COLUMN sender_id VARCHAR"))
                if "device_id" not in existing_cols:
                    conn.execute(text("ALTER TABLE scan_history ADD COLUMN device_id VARCHAR"))
                if "sanitized_content" not in existing_cols:
                    conn.execute(text("ALTER TABLE scan_history ADD COLUMN sanitized_content TEXT"))
                if "raw_content_stored" not in existing_cols:
                    conn.execute(text("ALTER TABLE scan_history ADD COLUMN raw_content_stored BOOLEAN DEFAULT 0"))
                conn.commit()
            except Exception as e:
                print(f"DB auto-migration note: {e}")
