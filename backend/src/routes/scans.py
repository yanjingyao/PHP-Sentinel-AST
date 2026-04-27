"""
扫描路由 - 扫描任务管理和 WebSocket 进度推送
"""

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Dict, Optional
import uuid
import asyncio
from datetime import datetime

from database import async_session_maker, get_db
from models import Scan, Project, File, Vulnerability
from schemas import ScanCreate, ScanResponse, ScanProgress, VulnerabilityResponse
from services.ast_engine import ASTEngine
from services.file_service import file_service
from dependencies import get_project_or_404, get_vuln_count, build_scan_response

router = APIRouter(prefix="/api/scans", tags=["scans"])

# 存储 WebSocket 连接
active_connections: Dict[str, WebSocket] = {}


@router.post("/", response_model=ScanResponse)
async def create_scan(scan: ScanCreate, db: AsyncSession = Depends(get_db)):
    """创建新的扫描任务（如果项目已有扫描记录，则删除旧记录）"""
    await get_project_or_404(db, scan.project_id)

    # 检查项目是否已有扫描记录
    existing_result = await db.execute(
        select(Scan).where(
            Scan.project_id == scan.project_id,
            Scan.is_webshell_mode == scan.is_webshell_mode
        )
    )
    existing_scans = existing_result.scalars().all()

    # 删除旧的扫描记录及其漏洞
    for old_scan in existing_scans:
        # 删除关联的漏洞
        await db.execute(
            Vulnerability.__table__.delete().where(Vulnerability.scan_id == old_scan.id)
        )
        # 删除旧扫描记录
        await db.delete(old_scan)

    if existing_scans:
        await db.commit()
        print(f"[create_scan] Deleted {len(existing_scans)} existing scans for project {scan.project_id}")

    scan_id = str(uuid.uuid4())
    new_scan = Scan(
        id=scan_id,
        project_id=scan.project_id,
        status="pending",
        total_files=file_service.count_project_files(scan.project_id),
        is_webshell_mode=scan.is_webshell_mode,
        created_at=datetime.utcnow(),
    )

    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)

    # If vulnerabilities are provided from frontend, save them directly
    if scan.vulnerabilities:
        for v_data in scan.vulnerabilities:
            db_vuln = Vulnerability(
                id=v_data.id or str(uuid.uuid4()),
                scan_id=scan_id,
                project_id=scan.project_id,
                type=v_data.type,
                level=v_data.level,
                line=v_data.line,
                file_name=v_data.file_name,
                snippet=v_data.snippet,
                description=v_data.description,
                source=v_data.source or "",
                sink=v_data.sink or "",
                created_at=datetime.utcnow(),
            )
            db.add(db_vuln)

        # Update scan status to completed
        new_scan.status = "completed"
        new_scan.completed_at = datetime.utcnow()
        new_scan.scanned_files = new_scan.total_files
        await db.commit()
    else:
        # 启动后台扫描任务 (legacy mode)
        asyncio.create_task(run_scan_task(scan_id, scan.project_id, scan.is_webshell_mode, scan.rule_states))

    vuln_count = await get_vuln_count(db, scan_id)
    return build_scan_response(new_scan, vuln_count)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """获取扫描任务详情"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="扫描任务不存在")

    vuln_count = await get_vuln_count(db, scan_id)
    return build_scan_response(scan, vuln_count)


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """删除单个扫描记录及其漏洞"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="扫描任务不存在")

    # 删除扫描记录（级联删除关联的漏洞）
    await db.delete(scan)
    await db.commit()

    return {"message": "扫描记录已删除"}


@router.get("/project/{project_id}", response_model=List[ScanResponse])
async def get_project_scans(project_id: str, db: AsyncSession = Depends(get_db)):
    """获取项目的所有扫描记录"""
    await get_project_or_404(db, project_id)

    # 获取该项目的所有扫描记录
    result = await db.execute(
        select(Scan).where(Scan.project_id == project_id).order_by(Scan.created_at.desc())
    )
    scans = result.scalars().all()

    scan_responses = []
    for scan in scans:
        vuln_count = await get_vuln_count(db, scan.id)
        scan_responses.append(build_scan_response(scan, vuln_count))

    return scan_responses


@router.websocket("/{scan_id}/ws")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """WebSocket 连接用于实时推送扫描进度"""
    await websocket.accept()
    active_connections[scan_id] = websocket

    try:
        while True:
            # 保持连接活跃
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        if scan_id in active_connections:
            del active_connections[scan_id]


async def run_scan_task(scan_id: str, project_id: str, is_webshell_mode: bool, rule_states: Optional[Dict[str, bool]] = None):
    """后台扫描任务"""
    engine = ASTEngine()

    async with async_session_maker() as db:
        # 从数据库加载自定义规则
        from models import Rule
        result = await db.execute(select(Rule).where(Rule.is_built_in == False))
        custom_rules = result.scalars().all()

        # 添加自定义规则到引擎
        for rule in custom_rules:
            from services.ast_engine import Rule as EngineRule, VulnerabilityType, RiskLevel
            engine.add_custom_rule(EngineRule(
                id=rule.id,
                name=rule.name,
                pattern=rule.pattern,
                type=VulnerabilityType(rule.type),
                level=RiskLevel(rule.level),
                enabled=rule.enabled,
                is_built_in=False,
                description=rule.description,
            ))

        print(f"[run_scan_task] Loaded {len(custom_rules)} custom rules")

        # 应用前端传递的规则状态（内置规则的启用/禁用）
        if rule_states:
            for rule_id, enabled in rule_states.items():
                engine.set_rule_state(rule_id, enabled)
            print(f"[run_scan_task] Applied {len(rule_states)} rule states from frontend")

        # 更新扫描状态为运行中
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        await db.commit()

        # 获取所有项目文件
        project_files = file_service.get_project_files(project_id)
        scan.total_files = len(project_files)
        await db.commit()

        all_vulnerabilities = []

        async def progress_callback(current: int, total: int, file_name: str):
            """进度回调"""
            scan.scanned_files = current + 1
            await db.commit()

            progress = ScanProgress(
                scan_id=scan_id,
                status="running",
                total_files=total,
                scanned_files=current + 1,
                progress_percentage=(current + 1) / total * 100,
                current_file=file_name,
                vulnerabilities_found=len(all_vulnerabilities),
            )

            # 通过 WebSocket 推送进度
            if scan_id in active_connections:
                try:
                    await active_connections[scan_id].send_json(progress.dict())
                except:
                    pass

        # 执行扫描
        for i, (file_name, content) in enumerate(project_files):
            await progress_callback(i, scan.total_files, file_name)

            vulns = await engine.scan_file(file_name, content, is_webshell_mode)
            all_vulnerabilities.extend(vulns)

        # 保存漏洞到数据库
        for vuln in all_vulnerabilities:
            db_vuln = Vulnerability(
                id=vuln.id,
                scan_id=scan_id,
                project_id=project_id,
                type=vuln.type.value,
                level=vuln.level.value,
                line=vuln.line,
                file_name=vuln.file_name,
                snippet=vuln.snippet,
                description=vuln.description,
                source=vuln.source,
                sink=vuln.sink,
                created_at=datetime.utcnow(),
            )
            db.add(db_vuln)

        # 完成扫描
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        await db.commit()

        # 发送完成消息
        if scan_id in active_connections:
            try:
                await active_connections[scan_id].send_json(
                    {
                        "scan_id": scan_id,
                        "status": "completed",
                        "vulnerabilities": [v.dict() for v in all_vulnerabilities],
                    }
                )
            except:
                pass
