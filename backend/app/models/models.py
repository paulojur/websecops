from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, UniqueConstraint, JSON
from sqlalchemy.sql import func
from ..core.database import Base

class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True, nullable=False)
    technologies = Column(JSON, default={}) # e.g. {"server": "Nginx", "framework": "Django"}
    vuln_status = Column(String, default="UNKNOWN") # SECURE, VULNERABLE, UNKNOWN
    last_scan = Column(DateTime(timezone=True), nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True, nullable=False)
    title = Column(String)
    description = Column(Text)
    severity = Column(String) # CRITICAL, HIGH, MEDIUM, LOW
    score = Column(Float, default=0.0)
    published_date = Column(DateTime(timezone=True))
    last_modified_date = Column(DateTime(timezone=True))
    source = Column(String) # NVD, ExploitDB
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Intelligence(Base):
    __tablename__ = "intelligence"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, index=True) # TheHackerNews, CyberPress, OWASP
    title = Column(String)
    limit = Column(String) # unique identifier or link to prevent duplicates
    link = Column(String, unique=True, index=True)
    summary = Column(Text)
    published_date = Column(DateTime(timezone=True))
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
