"""
Database models for jsanalsys.
Uses SQLAlchemy with SQLite backend for persistent project/asset storage.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean,
    ForeignKey, create_engine, Index, JSON
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker, Session


class Base(DeclarativeBase):
    pass


class Project(Base):
    """A scanning project targeting a domain/URL."""
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    target_url = Column(String(2048), nullable=False)
    scope_patterns = Column(Text, default="[]")  # JSON list of regex patterns
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes = Column(Text, default="")

    assets = relationship("Asset", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")

    @property
    def scope_list(self) -> list:
        try:
            return json.loads(self.scope_patterns)
        except Exception:
            return []

    @scope_list.setter
    def scope_list(self, value: list):
        self.scope_patterns = json.dumps(value)

    def __repr__(self):
        return f"<Project id={self.id} name={self.name!r} target={self.target_url!r}>"


class Asset(Base):
    """A discovered JS/HTML asset belonging to a project."""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    url = Column(String(2048), nullable=False)
    asset_type = Column(String(50), default="javascript")  # javascript, html, sourcemap, chunk
    content_hash = Column(String(64), nullable=True)       # SHA256
    content = Column(Text, nullable=True)                  # Raw content
    beautified_content = Column(Text, nullable=True)       # Beautified JS
    source_mapped_content = Column(Text, nullable=True)    # Source map reconstructed
    is_chunk = Column(Boolean, default=False)
    chunk_id = Column(String(255), nullable=True)          # Webpack/Vite chunk ID
    parent_url = Column(String(2048), nullable=True)       # URL that linked to this asset
    status_code = Column(Integer, nullable=True)
    content_length = Column(Integer, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    analyzed = Column(Boolean, default=False)
    has_sourcemap = Column(Boolean, default=False)
    sourcemap_url = Column(String(2048), nullable=True)

    project = relationship("Project", back_populates="assets")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_asset_project_url", "project_id", "url"),
    )

    def __repr__(self):
        return f"<Asset id={self.id} type={self.asset_type!r} url={self.url!r}>"


class Finding(Base):
    """A security finding extracted from an asset."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    finding_type = Column(String(100), nullable=False)  # endpoint, secret, sink, hostname, etc.
    category = Column(String(100), nullable=True)       # api_key, aws_key, jwt, etc.
    value = Column(Text, nullable=False)                # The extracted value
    context = Column(Text, nullable=True)               # Surrounding code snippet
    line_number = Column(Integer, nullable=True)
    confidence = Column(String(20), default="medium")   # high, medium, low
    severity = Column(String(20), default="info")       # critical, high, medium, low, info
    is_bookmarked = Column(Boolean, default=False)
    notes = Column(Text, default="")
    discovered_at = Column(DateTime, default=datetime.utcnow)
    pattern_name = Column(String(255), nullable=True)   # Which pattern matched

    project = relationship("Project", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")

    __table_args__ = (
        Index("idx_finding_project_type", "project_id", "finding_type"),
        Index("idx_finding_type_value", "finding_type", "value"),
    )

    def __repr__(self):
        return f"<Finding id={self.id} type={self.finding_type!r} value={self.value[:50]!r}>"


class CustomPattern(Base):
    """User-defined analysis patterns."""
    __tablename__ = "custom_patterns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True)  # None = global
    name = Column(String(255), nullable=False)
    pattern_type = Column(String(50), default="regex")   # regex, derived, script
    pattern = Column(Text, nullable=False)               # The regex/script
    finding_type = Column(String(100), nullable=False)   # Output finding type
    severity = Column(String(20), default="info")
    description = Column(Text, default="")
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<CustomPattern id={self.id} name={self.name!r} type={self.pattern_type!r}>"


def get_db_path(project_dir: Optional[str] = None) -> str:
    """Return the SQLite DB path."""
    if project_dir:
        return str(Path(project_dir) / "jsanalsys.db")
    home = Path.home() / ".jsanalsys"
    home.mkdir(exist_ok=True)
    return str(home / "jsanalsys.db")


def init_db(db_path: Optional[str] = None) -> tuple:
    """Initialize the database, return (engine, SessionLocal)."""
    path = db_path or get_db_path()
    engine = create_engine(f"sqlite:///{path}", echo=False)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    return engine, SessionLocal


def get_session(db_path: Optional[str] = None) -> Session:
    """Get a new DB session."""
    _, SessionLocal = init_db(db_path)
    return SessionLocal()
