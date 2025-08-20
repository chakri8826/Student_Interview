from sqlmodel import SQLModel,create_engine,Session
import os
from dotenv import load_dotenv

load_dotenv()  # load variables from .env

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL, echo=True)  # for creating the database we need to create a engine

def  create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session