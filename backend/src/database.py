from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool
import os

# SQLite 数据库路径
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./phpsentinel.db")

# 创建异步引擎
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    poolclass=NullPool,
)

# 创建异步会话工厂
async_session_maker = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

# 声明基类
Base = declarative_base()


# 依赖注入函数
async def get_db():
    """获取数据库会话"""
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()
