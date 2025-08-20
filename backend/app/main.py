from fastapi import FastAPI
from app.database import create_db_and_tables
from contextlib import asynccontextmanager
from app.routes import user_routes

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(lifespan=lifespan)
 
app.include_router(user_routes.router)

