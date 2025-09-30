# app.py
"""
Main application runner for NPS Integration API
"""
from main import app
from api_endpoints import router

# Include the API router
app.include_router(router, prefix="/api", tags=["NPS Operations"])

if __name__ == "__main__":
    import uvicorn

    print("\n" + "="*60)
    print("🚀 Starting NPS Integration API Server")
    print("="*60)
    print("\n📡 API will be available at: http://localhost:8000")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("📊 Alternative Docs: http://localhost:8000/redoc")
    print("\n💡 Available Endpoints:")
    print("   POST /api/send-payment     - Send payment to NPS")
    print("   POST /api/receive-payment  - Receive payment from NPS")
    print("   POST /api/test-connection  - Test NPS connection")
    print("   GET  /health               - Health check")
    print("   GET  /                     - API info")
    print("\n" + "="*60 + "\n")

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )