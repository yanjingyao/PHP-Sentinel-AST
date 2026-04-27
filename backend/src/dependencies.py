from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from models import Project, Vulnerability
from schemas import ScanResponse


async def get_project_or_404(db: AsyncSession, project_id: str):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    return project


async def get_vuln_count(db: AsyncSession, scan_id: str) -> int:
    result = await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.scan_id == scan_id)
    )
    return result.scalar() or 0


def build_scan_response(scan, vuln_count: int) -> ScanResponse:
    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        total_files=scan.total_files,
        scanned_files=scan.scanned_files,
        is_webshell_mode=scan.is_webshell_mode,
        created_at=scan.created_at,
        vulnerability_count=vuln_count,
    )
