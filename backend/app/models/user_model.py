from sqlmodel import SQLModel, Field
from pydantic import EmailStr, constr
from typing import Optional

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    
    name: constr(min_length=3, max_length=50)
    
    email: EmailStr = Field(unique=True, index=True)
    
    password: constr(min_length=8, max_length=128)
    
    city: Optional[constr(max_length=50)] = None
