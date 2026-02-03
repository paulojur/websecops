from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import vulnerabilities, intelligence, zap, targets
from app.core.database import engine, Base
from app.models import models

app = FastAPI(title="CyberRisk Intel API", version="0.1.0")

# Create Database Tables on Startup
@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])
app.include_router(intelligence.router, prefix="/api/v1/intelligence", tags=["intelligence"])
app.include_router(zap.router, prefix="/api/v1/zap", tags=["zap"])
app.include_router(targets.router, prefix="/api/v1/targets", tags=["targets"])

@app.get("/")
def read_root():
    return {"status": "online", "system": "CyberRisk Intelligence Platform"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}
