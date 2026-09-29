import os
from datetime import datetime
from typing import Optional

import pandas as pd
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database.db import get_db, init_db
from backend.database import models
from backend.detection import engine as detection_engine
from backend.config import DEFAULT_DETECTION_CONFIG, CORS_ALLOW_ORIGINS


# Create the FastAPI app
app = FastAPI(
    title="Psybeam Security Monitor",
    version="1.0.0"
)


# Allow the dashboard to communicate with the API
app.add_middleware(
    CORSMiddleware,
    # which sites can call this API
    allow_origins=CORS_ALLOW_ORIGINS,
    # Allow GET, POST, etc from those sites
    allow_methods=["*"],
    # Allow any request headers
    allow_headers=["*"],
)


# Find the sample log file
SAMPLE_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "sample_logs",
    "auth.log"
)


# Create the database when the API starts
@app.on_event("startup")
def on_startup():
    init_db()

