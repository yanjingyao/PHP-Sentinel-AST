"""
项目路由 - 项目管理 API
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List
import uuid
from datetime import datetime

from database import get_db
from models import Project, File
from schemas import ProjectCreate, ProjectResponse, ProjectDetailResponse, FileTreeNode
from services.file_service import file_service
from dependencies import get_project_or_404

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.post("/", response_model=ProjectResponse)
async def create_project(project: ProjectCreate, db: AsyncSession = Depends(get_db)):
    """创建新项目"""
    project_id = str(uuid.uuid4())
    new_project = Project(
        id=project_id,
        name=project.name,
        description=project.description,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    db.add(new_project)
    await db.commit()
    await db.refresh(new_project)

    return ProjectResponse(
        id=new_project.id,
        name=new_project.name,
        description=new_project.description,
        created_at=new_project.created_at,
        updated_at=new_project.updated_at,
        file_count=0,
        last_scan_at=None,
    )


@router.get("/", response_model=List[ProjectResponse])
async def list_projects(db: AsyncSession = Depends(get_db)):
    """获取所有项目列表"""
    result = await db.execute(select(Project))
    projects = result.scalars().all()

    response = []
    for project in projects:
        # 获取文件数量
        file_count = await db.execute(
            select(func.count(File.id)).where(File.project_id == project.id)
        )

        response.append(
            ProjectResponse(
                id=project.id,
                name=project.name,
                description=project.description,
                created_at=project.created_at,
                updated_at=project.updated_at,
                file_count=file_count.scalar(),
                last_scan_at=None,  # 可以后续添加
            )
        )

    return response


@router.get("/{project_id}", response_model=ProjectDetailResponse)
async def get_project(project_id: str, db: AsyncSession = Depends(get_db)):
    """获取项目详情"""
    project = await get_project_or_404(db, project_id)

    # 获取文件树
    file_tree = file_service.get_file_tree(project_id)

    return ProjectDetailResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        created_at=project.created_at,
        updated_at=project.updated_at,
        file_count=len(project.files),
        last_scan_at=None,
        files=[],  # 简化处理
        file_tree=file_tree,
    )


@router.delete("/{project_id}")
async def delete_project(project_id: str, db: AsyncSession = Depends(get_db)):
    """删除项目及其所有关联数据"""
    project = await get_project_or_404(db, project_id)

    # 删除数据库记录
    await db.delete(project)
    await db.commit()

    # 删除文件系统中的文件
    await file_service.delete_project_files(project_id)

    return {"message": "项目已删除"}
