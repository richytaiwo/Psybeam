import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base


# Get the db location from the environment and use psybeam.db if no location  given
DB_PATH = os.environ.get("PSYBEAM_DB_PATH", "psybeam.db")

DATABASE_URL = f"sqlite:///{DB_PATH}"


# Create the db connection
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)


# Create db sessions
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


# Base class for the db models
Base = declarative_base()


def get_db():
    # Open a db session
    db = SessionLocal()

    try:
        yield db
    finally:
        # Close the session when it is finished
        db.close()


def init_db():
    # Import the models for sqlalchemy 
    from backend.database import models  # noqa: F401

    # Create the db tables
    Base.metadata.create_all(bind=engine)