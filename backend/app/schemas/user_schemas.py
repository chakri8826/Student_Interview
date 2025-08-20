from pydantic import BaseModel, EmailStr, constr
from typing import Optional

class CreateUser(BaseModel):
    name: constr(min_length=3, max_length=50)
    email: EmailStr
    password: constr(min_length=8, max_length=128)
    city: Optional[constr(max_length=50)] = None
 
class LoginUser(BaseModel):
    email: EmailStr
    password: str

# Optional: token response after login
class Token(BaseModel):
    access_token: str
    token_type: str
