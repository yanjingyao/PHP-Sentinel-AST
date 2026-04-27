"""
文件服务 - 处理文件上传和目录结构
"""

import os
import shutil
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
import aiofiles
from datetime import datetime


class FileService:
    """文件服务 - 处理 PHP 文件上传和目录扫描"""

    def __init__(self, upload_dir: str = "./uploads"):
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    async def save_file(self, project_id: str, file_path: str, content: str) -> str:
        """保存单个文件到项目目录"""
        project_dir = self.upload_dir / project_id
        project_dir.mkdir(parents=True, exist_ok=True)

        # 构建完整路径
        full_path = project_dir / file_path.lstrip("/")
        full_path.parent.mkdir(parents=True, exist_ok=True)

        # 异步写入文件
        async with aiofiles.open(full_path, "w", encoding="utf-8") as f:
            await f.write(content)

        return str(full_path.relative_to(self.upload_dir))

    async def save_uploaded_file(
        self, project_id: str, file_name: str, content: bytes
    ) -> str:
        """保存上传的二进制文件"""
        project_dir = self.upload_dir / project_id
        project_dir.mkdir(parents=True, exist_ok=True)

        file_path = project_dir / file_name
        async with aiofiles.open(file_path, "wb") as f:
            await f.write(content)

        return str(file_path.relative_to(self.upload_dir))

    async def read_file(self, project_id: str, file_path: str) -> Optional[str]:
        """读取文件内容"""
        full_path = self.upload_dir / project_id / file_path.lstrip("/")

        if not full_path.exists():
            return None

        try:
            async with aiofiles.open(full_path, "r", encoding="utf-8") as f:
                return await f.read()
        except UnicodeDecodeError:
            # 尝试其他编码
            try:
                async with aiofiles.open(full_path, "r", encoding="gbk") as f:
                    return await f.read()
            except:
                return None

    async def delete_file(self, project_id: str, file_path: str) -> bool:
        """删除文件"""
        full_path = self.upload_dir / project_id / file_path.lstrip("/")

        try:
            if full_path.exists():
                full_path.unlink()
            return True
        except Exception:
            return False

    async def delete_project_files(self, project_id: str) -> bool:
        """删除整个项目的文件"""
        project_dir = self.upload_dir / project_id

        try:
            if project_dir.exists():
                shutil.rmtree(project_dir)
            return True
        except Exception:
            return False

    def get_file_tree(self, project_id: str) -> List[Dict[str, Any]]:
        """获取项目文件树结构"""
        project_dir = self.upload_dir / project_id

        if not project_dir.exists():
            return []

        def build_tree(path: Path) -> Dict[str, Any]:
            node = {
                "name": path.name,
                "path": str(path.relative_to(project_dir)),
                "type": "directory" if path.is_dir() else "file",
            }

            if path.is_dir():
                node["children"] = [
                    build_tree(child) for child in sorted(path.iterdir())
                ]
            else:
                node["size"] = path.stat().st_size

            return node

        # 获取根目录下的所有直接子项
        result = []
        for item in sorted(project_dir.iterdir()):
            result.append(build_tree(item))

        return result

    def get_project_files(self, project_id: str) -> List[Tuple[str, str]]:
        """获取项目中的所有文本文件（路径和内容）"""
        project_dir = self.upload_dir / project_id
        files = []

        if not project_dir.exists():
            return files

        for file_path in project_dir.rglob("*"):
            # 跳过目录和二进制文件
            if not file_path.is_file():
                continue

            # 尝试读取为文本文件
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                relative_path = str(file_path.relative_to(project_dir))
                files.append((relative_path, content))
            except Exception:
                # 跳过无法读取的文件（可能是二进制文件）
                continue

        return files

    def count_project_files(self, project_id: str) -> int:
        """统计项目文件数量"""
        project_dir = self.upload_dir / project_id

        if not project_dir.exists():
            return 0

        # 只统计能作为文本读取的文件
        count = 0
        for file_path in project_dir.rglob("*"):
            if file_path.is_file():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        f.read()
                    count += 1
                except Exception:
                    continue
        return count

    async def upload_directory(
        self, project_id: str, files: List[Tuple[str, bytes]]
    ) -> int:
        """上传整个目录"""
        project_dir = self.upload_dir / project_id
        project_dir.mkdir(parents=True, exist_ok=True)

        uploaded_count = 0
        for file_path, content in files:
            full_path = project_dir / file_path.lstrip("/")
            full_path.parent.mkdir(parents=True, exist_ok=True)

            async with aiofiles.open(full_path, "wb") as f:
                await f.write(content)

            uploaded_count += 1

        return uploaded_count


# 全局实例
file_service = FileService()
