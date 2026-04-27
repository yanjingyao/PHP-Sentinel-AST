"""
文件上传路由 - 处理项目文件上传
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File as FastAPIFile
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
import uuid
import zipfile
import io
from datetime import datetime

from database import get_db
from models import Project, File as FileModel
from schemas import FileResponse, FileCreate
from services.file_service import file_service
from dependencies import get_project_or_404

router = APIRouter(prefix="/api/projects", tags=["files"])


@router.post("/{project_id}/upload")
async def upload_file(
    project_id: str,
    file: UploadFile = FastAPIFile(...),
    path: str = "",
    db: AsyncSession = Depends(get_db),
):
    """上传单个文件到项目"""
    await get_project_or_404(db, project_id)

    # 接受所有文本文件类型
    # 检查文件是否可以作为文本解码
    content = await file.read()
    try:
        content_str = content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content_str = content.decode("gbk")
        except:
            raise HTTPException(status_code=400, detail="文件编码不支持（仅支持 UTF-8 或 GBK 编码的文本文件）")

    # 构建文件路径
    file_path = f"{path}/{file.filename}" if path else file.filename

    # 保存文件
    await file_service.save_file(project_id, file_path, content_str)

    # 保存到数据库
    file_id = str(uuid.uuid4())
    new_file = FileModel(
        id=file_id,
        project_id=project_id,
        name=file.filename,
        path=file_path,
        content=content_str,
        size=len(content),
        created_at=datetime.utcnow(),
    )
    db.add(new_file)
    await db.commit()

    return FileResponse(
        id=file_id,
        project_id=project_id,
        name=file.filename,
        path=file_path,
        content=content_str,
        size=len(content),
        created_at=datetime.utcnow(),
    )


@router.post("/{project_id}/upload-zip")
async def upload_zip(
    project_id: str,
    file: UploadFile = FastAPIFile(...),
    db: AsyncSession = Depends(get_db),
):
    """上传 ZIP 压缩包（自动解压 PHP 文件）"""
    await get_project_or_404(db, project_id)

    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="只支持 ZIP 文件")

    # 读取 ZIP 文件
    content = await file.read()

    uploaded_files = []

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            for zip_info in zf.infolist():
                # 跳过目录
                if zip_info.filename.endswith('/'):
                    continue

                # 读取文件内容
                file_content = zf.read(zip_info.filename)

                # 尝试解码为文本，跳过二进制文件
                try:
                    content_str = file_content.decode("utf-8")
                except UnicodeDecodeError:
                    try:
                        content_str = file_content.decode("gbk")
                    except:
                        continue  # 跳过无法解码的二进制文件

                # 保存文件
                await file_service.save_file(
                    project_id, zip_info.filename, content_str
                )

                # 保存到数据库
                file_id = str(uuid.uuid4())
                new_file = FileModel(
                    id=file_id,
                    project_id=project_id,
                    name=zip_info.filename.split("/")[-1],
                    path=zip_info.filename,
                    content=content_str,
                    size=len(file_content),
                    created_at=datetime.utcnow(),
                )
                db.add(new_file)
                uploaded_files.append(new_file)

        await db.commit()

        return {
            "message": f"成功上传 {len(uploaded_files)} 个文件",
            "files": [
                {"id": f.id, "name": f.name, "path": f.path, "size": f.size}
                for f in uploaded_files
            ],
        }

    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="无效的 ZIP 文件")


@router.get("/{project_id}/files", response_model=List[FileResponse])
async def list_files(project_id: str, db: AsyncSession = Depends(get_db)):
    """获取项目文件列表"""
    result = await db.execute(
        select(FileModel).where(FileModel.project_id == project_id)
    )
    files = result.scalars().all()

    return [
        FileResponse(
            id=f.id,
            project_id=f.project_id,
            name=f.name,
            path=f.path,
            content=f.content,
            size=f.size,
            created_at=f.created_at,
        )
        for f in files
    ]


@router.get("/{project_id}/files/{file_id}")
async def get_file_content(
    project_id: str, file_id: str, db: AsyncSession = Depends(get_db)
):
    """获取文件内容"""
    result = await db.execute(
        select(FileModel).where(
            FileModel.id == file_id, FileModel.project_id == project_id
        )
    )
    file = result.scalar_one_or_none()

    if not file:
        raise HTTPException(status_code=404, detail="文件不存在")

    return {
        "id": file.id,
        "name": file.name,
        "path": file.path,
        "content": file.content,
        "size": file.size,
    }


@router.get("/{project_id}/file-tree")
async def get_file_tree(project_id: str, db: AsyncSession = Depends(get_db)):
    """获取项目文件树"""
    await get_project_or_404(db, project_id)
    tree = file_service.get_file_tree(project_id)
    return tree
