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
import secrets
import string

router = APIRouter()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
LINKEDIN_REDIRECT_URI = os.getenv("LINKEDIN_REDIRECT_URI")


MICROSOFT_CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID")
MICROSOFT_CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET")
MICROSOFT_REDIRECT_URI = os.getenv("MICROSOFT_REDIRECT_URI")
MICROSOFT_TENANT_ID = os.getenv("MICROSOFT_TENANT_ID", "common") 


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

oauth.register(
    name='linkedin',
    client_id=os.getenv('LINKEDIN_CLIENT_ID'),
    client_secret=os.getenv('LINKEDIN_CLIENT_SECRET'),
    access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
    authorize_url='https://www.linkedin.com/oauth/v2/authorization',
    api_base_url='https://api.linkedin.com/v2/',
    client_kwargs={
        'scope': 'openid profile email',
        'token_endpoint_auth_method': 'client_secret_post'
    }
)

oauth.register(
    name='microsoft',
    client_id=MICROSOFT_CLIENT_ID,
    client_secret=MICROSOFT_CLIENT_SECRET,
    access_token_url=f'https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/token',
    authorize_url=f'https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize',
    api_base_url='https://graph.microsoft.com/v1.0/',
    client_kwargs={
        'scope': 'openid email profile User.Read',
        'response_type': 'code'
    }
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



@router.get("/linkedin")
async def login_linkedin(request: Request):
    return await oauth.linkedin.authorize_redirect(request, redirect_uri=LINKEDIN_REDIRECT_URI)


@router.get("/linkedin-login")  
async def linkedin_login(request: Request, session: SessionDep):
    code = request.query_params.get("code")
    
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not found")
    
    try:
        # Exchange code for tokens
        token_url = "https://www.linkedin.com/oauth/v2/accessToken"
        
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": os.getenv("LINKEDIN_CLIENT_ID"),
            "client_secret": os.getenv("LINKEDIN_CLIENT_SECRET"),
            "redirect_uri": os.getenv("LINKEDIN_REDIRECT_URI")
        }
        
        # Make the token exchange request with proper headers
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url, 
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            # Check response status
            if response.status_code != 200:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Token exchange failed: {response.text}"
                )
            
            tokens = response.json()
        
        # Check if token exchange was successful
        if "access_token" not in tokens:
            error_desc = tokens.get("error_description", "Unknown error")
            raise HTTPException(status_code=400, detail=f"Failed to get access token: {error_desc}")
        
        # Get user info from LinkedIn
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        user_data = None
        
        async with httpx.AsyncClient() as client:
            # Try userinfo endpoint first
            user_response = await client.get(
                "https://api.linkedin.com/v2/userinfo", 
                headers=headers
            )
            
            if user_response.status_code == 200:
                user_data = user_response.json()
            else:
                # Fallback to LinkedIn's specific endpoints
                # Get profile
                profile_response = await client.get(
                    "https://api.linkedin.com/v2/people/~?projection=(id,firstName,lastName)",
                    headers=headers
                )
                
                # Get email
                email_response = await client.get(
                    "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
                    headers=headers
                )
                
                if profile_response.status_code != 200:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Failed to get user profile: {profile_response.text}"
                    )
                
                profile_data = profile_response.json()
                
                # Extract email
                user_email = None
                if email_response.status_code == 200:
                    email_data = email_response.json()
                    elements = email_data.get("elements", [])
                    if elements:
                        user_email = elements[0].get("handle~", {}).get("emailAddress")
                
                if not user_email:
                    raise HTTPException(status_code=400, detail="Could not retrieve email from LinkedIn")
                
                # Extract name from LinkedIn's localized format
                first_name_data = profile_data.get("firstName", {}).get("localized", {})
                last_name_data = profile_data.get("lastName", {}).get("localized", {})
                
                # Get first available localized name
                first_name = list(first_name_data.values())[0] if first_name_data else ""
                last_name = list(last_name_data.values())[0] if last_name_data else ""
                full_name = f"{first_name} {last_name}".strip()
                
                user_data = {
                    "email": user_email,
                    "name": full_name,
                    "given_name": first_name,
                    "family_name": last_name
                }
        
        # Validate we have required data
        if not user_data or not user_data.get("email"):
            raise HTTPException(status_code=400, detail="Could not retrieve user data from LinkedIn")
        
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
            random_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            hashed_password = hash_password(random_password)
            
            # LinkedIn returns different format, handle name properly
            user_name = user_data.get("name") or f"{user_data.get('given_name', '')} {user_data.get('family_name', '')}".strip()
            if not user_name:
                user_name = "LinkedIn User"
            
            new_user = User(
                name=user_name,  # LinkedIn provides name
                email=user_data["email"],  # LinkedIn provides email
                password=hashed_password,  # Random password since they use OAuth
                city=None  # LinkedIn doesn't provide city, can be updated later
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

    

@router.get("/microsoft")
async def login_microsoft(request: Request):
    return await oauth.microsoft.authorize_redirect(request, redirect_uri=MICROSOFT_REDIRECT_URI)


@router.get("/microsoft-login")  
async def microsoft_login(request: Request, session: SessionDep):
    code = request.query_params.get("code")
    
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not found")
    
    try:
        # Exchange code for tokens
        token_url = f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/token"
        
        token_data = {
            "client_id": MICROSOFT_CLIENT_ID,
            "client_secret": MICROSOFT_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": MICROSOFT_REDIRECT_URI,
            "scope": "https://graph.microsoft.com/User.Read"
        }
        
        # Make the token exchange request
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url, 
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            # Check response status
            if response.status_code != 200:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Token exchange failed: {response.text}"
                )
            
            tokens = response.json()
        
        # Check if token exchange was successful
        if "access_token" not in tokens:
            error_desc = tokens.get("error_description", "Unknown error")
            raise HTTPException(status_code=400, detail=f"Failed to get access token: {error_desc}")
        
        # Get user info from Microsoft Graph API
        user_info_url = "https://graph.microsoft.com/v1.0/me"
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        
        async with httpx.AsyncClient() as client:
            user_response = await client.get(user_info_url, headers=headers)
            
            if user_response.status_code != 200:
                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to get user info: {user_response.text}"
                )
            
            user_data = user_response.json()
        
        # Validate we have required data
        if not user_data.get("mail") and not user_data.get("userPrincipalName"):
            raise HTTPException(status_code=400, detail="Could not retrieve email from Microsoft")
        
        # Microsoft can return email in 'mail' or 'userPrincipalName' field
        user_email = user_data.get("mail") or user_data.get("userPrincipalName")
        user_name = user_data.get("displayName", "Microsoft User")
        
        existing_user = session.exec(
            select(User).where(User.email == user_email)
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
            random_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            hashed_password = hash_password(random_password)
            
            new_user = User(
                name=user_name,  # Microsoft provides displayName
                email=user_email,  # Microsoft provides email
                password=hashed_password,  # Random password since they use OAuth
                city=None  # Microsoft doesn't provide city, can be updated later
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