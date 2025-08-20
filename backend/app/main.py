from fastapi import FastAPI
from app.database import create_db_and_tables
from contextlib import asynccontextmanager
from app.routes import user_routes
from starlette.middleware.sessions import SessionMiddleware
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "supersecret"),  # put a strong secret in .env
)

app.include_router(user_routes.router)

