from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI(title='VA-WebSec', description='Virtual Assistant for Web Security Testing')
from app.api.router import router as api_router
app.include_router(api_router, prefix='/api')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])
