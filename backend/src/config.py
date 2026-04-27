import os
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # 数据库配置
    DATABASE_URL: str = "sqlite+aiosqlite:///./phpsentinel.db"

    # AI 配置
    DEFAULT_AI_PROVIDER: str = "gemini"  # gemini, openai, moonshot
    DEFAULT_AI_MODEL: str = "gemini-pro"
    GEMINI_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    MOONSHOT_API_KEY: Optional[str] = None

    # 文件上传配置 - 使用绝对路径放在 backend 外部，避免 Vite 扫描
    UPLOAD_DIR: str = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "uploads_data")
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB

    # CORS 配置
    CORS_ORIGINS: list = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # 调试模式
    DEBUG: bool = False

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

# 确保上传目录存在
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
