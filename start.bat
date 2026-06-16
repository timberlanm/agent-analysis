@echo off
chcp 65001 >nul
title 研判分析工作台

echo ========================================
echo   研判分析工作台
echo ========================================
echo.

:: 检查 Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 未找到 Python，请先安装 Python 3.8+
    pause
    exit /b 1
)

:: 检查依赖
echo [1/3] 检查 Python 依赖...
pip show Flask >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] 安装 Python 依赖...
    pip install -r backend\requirements.txt
)

:: 检查前端依赖（使用本地缓存目录避免系统缓存权限问题）
echo [2/4] 检查前端依赖...
if not exist "frontend\node_modules\" (
    echo [INFO] 安装前端依赖...
    cd frontend
    set npm_config_cache=.npm-cache
    call npm install
    cd ..
)

:: 构建前端（必须，否则 Flask 托管源码浏览器无法运行）
echo [3/4] 构建前端...
cd frontend
call npm run build
cd ..

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
