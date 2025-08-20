from fastapi import FastAPI,Depends,HTTPException,APIRouter
from typing import Annotated
from sqlmodel import select
from fastapi.security import OAuth2PasswordRequestForm
from app.models.user_model import User
from app.auth import create_access_token,hash_password,verify_password,ACCESS_TOKEN_EXPIRE_MINUTES
from app.schemas.user_schemas import CreateUser,Token
from app.dependencies import SessionDep,get_curr_user
from datetime import timedelta

router = APIRouter()

@router.post("/register")
def register(session:SessionDep,user_data:CreateUser):  #Validation happens at CreateUser
    if session.exec(select(User).where(User.email==user_data.email)).first():    # Fetches the first row from the result.
        raise HTTPException(status_code=400,detail="Email is already registered")
    hash_pwd = hash_password(user_data.password)

    user = User(name=user_data.name,email=user_data.email,password=hash_pwd,city=user_data.password)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.post("/login",response_model=Token)
def login(session:SessionDep,form_data:Annotated[OAuth2PasswordRequestForm,Depends()]):
    user = session.exec(select(User).where(User.email==form_data.username)).first()

    if not user:
        raise HTTPException(status_code=404,detail="Invalid Credentials")

    pwd = verify_password(form_data.password,user.password)

    if not pwd:
        raise HTTPException(status_code=404,detail="Invalid Credentials")

    expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    token=create_access_token(data={"sub":user.email},expires_delta=expire)
    return {"access_token":token,"token_type":"bearer"}


@router.get("/profile")
def profile(current_user:Annotated[User,Depends(get_curr_user)]):
    return {"name":current_user,"email":current_user.email}