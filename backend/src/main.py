"""
FastAPI 主入口
PHP Sentinel 后端服务
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from database import engine, Base
from routes import (
    ai,
    files,
    network,
    projects,
    rules,
    scans,
    settings as settings_router,
    vulnerabilities,
)

# 配置日志
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时创建数据库表
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # 关闭时清理资源
    await engine.dispose()


app = FastAPI(
    title="PHP Sentinel API",
    description="PHP 漏洞检测引擎后端服务",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(projects.router)
app.include_router(files.router)
app.include_router(scans.router)
app.include_router(vulnerabilities.router)
app.include_router(ai.router)
app.include_router(settings_router.router)
app.include_router(rules.router)
app.include_router(network.router)


@app.get("/")
async def root():
    """根路径 - API 状态"""
    return {"status": "ok", "service": "PHP Sentinel API", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    """健康检查端点"""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
