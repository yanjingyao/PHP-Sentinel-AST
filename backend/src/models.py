from sqlalchemy import (
    Column,
    String,
    Integer,
    ForeignKey,
    Text,
    Boolean,
    DateTime,
    JSON,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    files = relationship("File", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    vulnerabilities = relationship(
        "Vulnerability", back_populates="project", cascade="all, delete-orphan"
    )


class File(Base):
    __tablename__ = "files"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    name = Column(String, nullable=False)
    path = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    size = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    project = relationship("Project", back_populates="files")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    status = Column(String, default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    total_files = Column(Integer, default=0)
    scanned_files = Column(Integer, default=0)
    is_webshell_mode = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    project = relationship("Project", back_populates="scans")
    vulnerabilities = relationship(
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    file_id = Column(String, ForeignKey("files.id"), nullable=True)

    type = Column(String, nullable=False)  # SQL注入, XSS等
    level = Column(String, nullable=False)  # CRITICAL, HIGH等
    line = Column(Integer, nullable=False)
    file_name = Column(String, nullable=False)
    snippet = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    source = Column(String, nullable=True)
    sink = Column(String, nullable=True)

    # AI 审计结果
    ai_assessment = Column(JSON, nullable=True)
    chat_history = Column(JSON, default=list)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="vulnerabilities")
    project = relationship("Project", back_populates="vulnerabilities")


class Rule(Base):
    __tablename__ = "rules"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    pattern = Column(String, nullable=False)
    type = Column(String, nullable=False)
    level = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    is_built_in = Column(Boolean, default=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AIConfig(Base):
    __tablename__ = "ai_configs"

    id = Column(String, primary_key=True, default="default")
    config = Column(JSON, nullable=False)  # 完整的 AI 配置对象
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class NetworkLog(Base):
    __tablename__ = "network_logs"

    id = Column(String, primary_key=True)
    method = Column(String, nullable=False)
    url = Column(String, nullable=False)
    request_headers = Column(Text, nullable=True)
    request_body = Column(Text, nullable=True)
    response_status = Column(Integer, nullable=False)
    response_status_text = Column(String, nullable=True)
    response_headers = Column(Text, nullable=True)
    response_body = Column(Text, nullable=True)
    duration = Column(Integer, nullable=False)  # ms
    size = Column(Integer, nullable=False)  # bytes
    created_at = Column(DateTime(timezone=True), server_default=func.now())
