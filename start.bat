@echo off
chcp 65001 >nul
cd /d "%~dp0"
title 研判分析工作台
setlocal enabledelayedexpansion

:: Load machine-local database settings. The file is gitignored and may hold
:: development credentials without changing the shared launcher.
if exist ".env.postgres.local" (
    for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env.postgres.local") do (
        if not "%%A"=="" if not defined %%A set "%%A=%%B"
    )
)

echo ========================================
echo   研判分析工作台
echo ========================================
echo.

:: 可选：--rebuild 强制重建（正常使用无需，脚本会自动判断）
set "REBUILD=0"
if /i "%~1"=="--rebuild" set "REBUILD=1"

:: 检查 Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] 未找到 Python，请先安装 Python 3.8+
    pause
    exit /b 1
)

:: 检查后端依赖
echo [1/4] 检查 Python 依赖...
python -c "import flask, sqlalchemy, psycopg, alembic" >nul 2>&1
if errorlevel 1 (
    echo [INFO] 安装 Python 依赖...
    pip install -r backend\requirements.txt
)

:: 自动判断是否需要构建前端：缺产物、或源码比产物新，则重建；否则跳过（无需手动选择）
:: 说明：本脚本不使用 goto/标签——UTF-8(含中文) 批处理里 goto 会因字节偏移错乱而报错，
::       改用 if/else 块 + 标志位，跨机器稳定。
set "BUILD_NEEDED=0"
if "%REBUILD%"=="1" set "BUILD_NEEDED=1"
if not exist "frontend\dist\index.html" set "BUILD_NEEDED=1"
if "!BUILD_NEEDED!"=="0" (
    where powershell >nul 2>&1
    if errorlevel 1 (
        set "BUILD_NEEDED=1"
    ) else (
        powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\need-build.ps1"
        if errorlevel 1 set "BUILD_NEEDED=1"
    )
)

:: 是否需要 Node（仅在装前端依赖或构建时需要；预置 dist 的离线部署无需 Node）
set "NEED_NODE=0"
if not exist "frontend\node_modules\" set "NEED_NODE=1"
if "!BUILD_NEEDED!"=="1" set "NEED_NODE=1"
if "!NEED_NODE!"=="1" (
    where node >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] 需要构建前端，但未找到 Node.js，请安装 Node.js 16+（含 npm）
        echo         下载： https://nodejs.org/
        echo         或在有网机器构建好 frontend\dist 后拷贝过来，即可免 Node 运行。
        pause
        exit /b 1
    )
)

:: 检查前端依赖（缺失才安装；使用本地缓存目录避免系统缓存权限问题）
echo [2/4] 检查前端依赖...
if not exist "frontend\node_modules\" (
    echo [INFO] 安装前端依赖...
    cd frontend
    set npm_config_cache=.npm-cache
    call npm install
    cd ..
)

:: 前端构建（自动：需要才构建）
echo [3/4] 前端构建...
if "!BUILD_NEEDED!"=="1" (
    echo [INFO] 检测到前端有更新或首次运行，正在构建...
    cd frontend
    call npm run build
    cd ..
) else (
    echo [INFO] 前端无改动，跳过构建
)

:: 启动后端
echo [4/4] 启动服务...
echo.
echo   后端 API: http://localhost:5000
echo   前端页面: http://localhost:5000
echo.
echo   按 Ctrl+C 停止服务
echo ========================================

:: 后台打开浏览器
start http://localhost:5000

:: 前台运行 Flask，Ctrl+C 可正常终止
python backend\app.py --serve-frontend
