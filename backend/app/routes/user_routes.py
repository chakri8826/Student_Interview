from fastapi import  Depends, HTTPException, APIRouter, Request
from typing import Annotated
from sqlmodel import select
from fastapi.security import OAuth2PasswordRequestForm
from app.models.user_model import User
from app.auth import create_access_token, hash_password, verify_password
from app.schemas.user_schemas import CreateUser, Token
from app.dependencies import SessionDep, get_curr_user
from datetime import timedelta
from google.auth.transport import requests as google_requests
from authlib.integrations.starlette_client import OAuth
import os
import httpx

router = APIRouter()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# Setup OAuth
oauth = OAuth()

oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)


@router.get("/google")
async def login_google(request: Request):
    return await oauth.google.authorize_redirect(request, redirect_uri=GOOGLE_REDIRECT_URI)
 
@router.get("/google-login")  
async def google_login(request: Request, session: SessionDep):
    code = request.query_params.get("code")
    
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not found")
    
    try:
        # Exchange code for tokens
        token_url = "https://oauth2.googleapis.com/token"
        
        token_data = {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": os.getenv("GOOGLE_REDIRECT_URI")
        }
        
        # Make the token exchange request
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=token_data)
            tokens = response.json()
        
        # Check if token exchange was successful
        if "access_token" not in tokens:
            raise HTTPException(status_code=400, detail="Failed to get access token")
        
        # Get user info from Google
        user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        
        async with httpx.AsyncClient() as client:
            user_response = await client.get(user_info_url, headers=headers)
            user_data = user_response.json()
        
        existing_user = session.exec(
            select(User).where(User.email == user_data["email"])
        ).first()
        
        if existing_user:
            # User exists, create access token and return
            expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": existing_user.email}, 
                expires_delta=expire
            )
            
            return {
                "message": "Login successful",
                "user": {
                    "id": existing_user.id,
                    "name": existing_user.name,
                    "email": existing_user.email,
                    "city": existing_user.city
                },
                "access_token": access_token,
                "token_type": "bearer"
            }
        
        else:
            import secrets
            import string
            random_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            hashed_password = hash_password(random_password)
            
            new_user = User(
                name=user_data.get("name", "Google User"),  # Google provides name
                email=user_data["email"],  # Google provides email
                password=hashed_password,  # Random password since they use OAuth
                city=None  # Google doesn't provide city, can be updated later
            )
            
            session.add(new_user)
            session.commit()
            session.refresh(new_user)
            
            # Create access token for new user
            expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": new_user.email}, 
                expires_delta=expire
            )
            
            return {
                "message": "Registration and login successful",
                "user": {
                    "id": new_user.id,
                    "name": new_user.name,
                    "email": new_user.email,
                    "city": new_user.city
                },
                "access_token": access_token,
                "token_type": "bearer"
            }
        
    except HTTPException:
        raise  
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Login failed: {str(e)}")
        
    
@router.post("/register")
def register(session:SessionDep,user_data:CreateUser):  
    if session.exec(select(User).where(User.email==user_data.email)).first():     
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