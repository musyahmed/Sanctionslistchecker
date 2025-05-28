import os
import uvicorn
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
import pyotp # For MFA
import uuid # For JWT jti claim

# Attempt to mock google.cloud.texttospeech.TextToSpeechClient before agent_module is imported
# This is to prevent `DefaultCredentialsError` during import time if the agent script initializes this client globally.
# This is especially important if GOOGLE_APPLICATION_CREDENTIALS are not set in the environment.
from unittest.mock import MagicMock, patch
mock_tts_client_instance = MagicMock()
# Patch the class itself to return a MagicMock instance when called
google_tts_client_patch = patch('google.cloud.texttospeech.TextToSpeechClient', return_value=mock_tts_client_instance)

# It's good practice to set a dummy OPENAI_API_KEY if it's not expected to be available
# and the imported module would fail without it. For this script, we assume it will be set in the environment.
# if "OPENAI_API_KEY" not in os.environ:
#     os.environ["OPENAI_API_KEY"] = "dummy_key_for_api_import" # Or handle appropriately

# Apply the patch before importing agent_module
with google_tts_client_patch:
    try:
        from agent_module import (
            get_user_data_from_vector_db,
            ask_llm,
            vector_db_client,  # This is None for mock_db
            # mock_vector_db_data is used internally by get_user_data_from_vector_db when client is None
            openai_client, # Ensure it's imported if ask_llm relies on it being initialized
        )
    except ImportError as e:
        print(f"Error importing from agent_module: {e}")
        # Handle module not found or other import errors if necessary
        raise RuntimeError(f"Could not import from agent_module.py: {e}") from e
    except RuntimeError as e:
        # This can catch the OPENAI_API_KEY not set error from agent_module
        print(f"RuntimeError during import of agent_module: {e}")
        print("Ensure OPENAI_API_KEY is set in your environment.")
        # Potentially set a dummy key here if absolutely necessary for the app to even load,
        # though it's better to have it set in the environment.
        if "OPENAI_API_KEY" not in os.environ and "OPENAI_API_KEY" in str(e):
             os.environ["OPENAI_API_KEY"] = "dummy_key_for_runtime" # Emergency dummy key
             print("Emergency dummy OPENAI_API_KEY set. Please set it properly in your environment.")
             # Retry import - this is a bit complex for an import block, better to ensure env setup
        raise

# --- Rate Limiting Setup ---
# In a production app, these rate limits should be configurable (e.g., via environment variables).
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Personal Banking Agent API",
    description="API for interacting with the Personal Banking Agent with JWT Authentication and Rate Limiting.",
    version="0.3.0", # Version incremented for rate limiting feature
)
# PRODUCTION DEPLOYMENT NOTE:
# Ensure this API is served over HTTPS in production.
# This is typically handled by a reverse proxy (e.g., Nginx, Traefik)
# or an API Gateway / Load Balancer that terminates SSL/TLS.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# --- JWT Configuration ---
SECRET_KEY = "your-super-secret-key-for-jwt" # In production, use a strong key from env var
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Password Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# --- User Models ---
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Username must be between 3 and 50 characters.")

class UserCreate(UserBase): # Inherits validated username from UserBase
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long.")

class UserLogin(UserBase): # For login form, username is part of OAuth2PasswordRequestForm. This model is not directly used for validation in /login but good for consistency.
    username: str # Overriding to remove Field validation for this specific model if not needed for /login
    password: str

class UserInDB(UserBase):
    hashed_password: str
    mfa_secret: str | None = None
    is_mfa_enabled: bool = False

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
    jti: str | None = None # Added jti field

# --- Mock User Database ---
# Stores username as key and UserInDB model as value
mock_user_db: dict[str, UserInDB] = {}

# --- Token Blocklist (for revoked tokens) ---
token_blocklist = set() # In-memory blocklist

# --- JWT Creation Utility ---
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15) # Default expiry
    to_encode.update({"exp": expire})
    to_encode["jti"] = str(uuid.uuid4()) # Add jti claim
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- OAuth2 Scheme ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- User Authentication Utility Functions ---
async def get_current_user_data(token: str = Depends(oauth2_scheme)) -> TokenData: # Renamed and changed return type
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    revoked_token_exception = HTTPException(
        status_code=401,
        detail="Token has been revoked",
        headers={"WWW-Authenticate": "Bearer"},
    )
    missing_jti_exception = HTTPException(
        status_code=401,
        detail="Token missing jti claim",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        jti: str | None = payload.get("jti")

        if username is None:
            raise credentials_exception
        if jti is None: # Check for jti presence
            raise missing_jti_exception
        if jti in token_blocklist: # Check if jti is in blocklist
            raise revoked_token_exception
            
        token_data = TokenData(username=username, jti=jti)
    except JWTError:
        raise credentials_exception
    
    # User existence check (still important)
    user = mock_user_db.get(token_data.username)
    if user is None:
        raise credentials_exception # Or a more specific "User not found for token"
    
    return token_data

async def get_current_active_user(token_data: TokenData = Depends(get_current_user_data)) -> UserInDB:
    # This function now takes TokenData and returns the UserInDB object
    # It assumes get_current_user_data has already validated the token including jti and blocklist
    user = mock_user_db.get(token_data.username)
    if not user: # Should not happen if get_current_user_data passed
        raise HTTPException(status_code=400, detail="User not found after token validation")
    return user


# --- Endpoints for Authentication ---
@app.post("/register", response_model=UserBase)
@limiter.limit("5/minute") # Example: 5 registrations per minute per IP
async def register_user(request: Request, user: UserCreate):
    if user.username in mock_user_db:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    # Initialize MFA fields for new user
    user_in_db = UserInDB(
        username=user.username, 
        hashed_password=hashed_password,
        mfa_secret=None,
        is_mfa_enabled=False
    )
    mock_user_db[user.username] = user_in_db
    return UserBase(username=user.username)

# --- MFA Utility Functions ---
def generate_mfa_secret() -> str:
    return pyotp.random_base32()

def get_provisioning_uri(username: str, secret: str) -> str:
    # Ensure issuer_name is URL-friendly if it contains spaces or special characters
    issuer_name = "MyBankingApp" 
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)

def verify_totp(secret: str, token: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

# --- Pydantic Models for MFA Endpoints ---
class MfaSetupResponse(BaseModel):
    provisioning_uri: str
    mfa_secret_for_testing: str # WARNING: For testing only. Remove in production.

class MfaVerifyRequest(BaseModel):
    totp_code: str

# --- Endpoints for MFA Setup ---
@app.post("/mfa/setup", response_model=MfaSetupResponse)
@limiter.limit("3/hour") # Stricter limit for MFA setup
async def mfa_setup(request: Request, current_active_user: UserInDB = Depends(get_current_active_user)): # Updated dependency
    if current_active_user.is_mfa_enabled: # Use current_active_user
        raise HTTPException(status_code=400, detail="MFA is already enabled for this user.")
    
    # Generate and store a new MFA secret (even if one exists but isn't enabled, overwrite for setup)
    mfa_secret = generate_mfa_secret()
    current_active_user.mfa_secret = mfa_secret # Store it, will be persisted if mock_user_db user object is updated
    # Note: In a real DB, you'd save the user object here. mock_user_db is in-memory, so changes to current_active_user reflect.
    
    provisioning_uri = get_provisioning_uri(current_active_user.username, mfa_secret) # Use current_active_user
    
    return MfaSetupResponse(
        provisioning_uri=provisioning_uri,
        mfa_secret_for_testing=mfa_secret # WARNING: For testing only
    )

@app.post("/mfa/verify")
@limiter.limit("5/minute") # Limit MFA verification attempts
async def mfa_verify(req: Request, request_data: MfaVerifyRequest, current_active_user: UserInDB = Depends(get_current_active_user)): # Updated dependency
    if current_active_user.is_mfa_enabled: # Use current_active_user
        raise HTTPException(status_code=400, detail="MFA is already enabled and verified.")
    if not current_active_user.mfa_secret: # Use current_active_user
        raise HTTPException(status_code=400, detail="MFA setup process not started. Please call /mfa/setup first.")
        
    if verify_totp(current_active_user.mfa_secret, request_data.totp_code): # Use current_active_user
        current_active_user.is_mfa_enabled = True # Use current_active_user
        # Again, in a real DB, save the user object.
        print(f"MFA successfully enabled for user: {current_active_user.username}") # Use current_active_user
        return {"message": "MFA enabled successfully."}
    else:
        raise HTTPException(status_code=400, detail="Invalid TOTP code.")

# --- Pydantic Models for MFA Login Flow ---
    
    # Generate and store a new MFA secret (even if one exists but isn't enabled, overwrite for setup)
    mfa_secret = generate_mfa_secret()
    current_user.mfa_secret = mfa_secret # Store it, will be persisted if mock_user_db user object is updated
    # Note: In a real DB, you'd save the user object here. mock_user_db is in-memory, so changes to current_user reflect.
    
    provisioning_uri = get_provisioning_uri(current_user.username, mfa_secret)
    
    return MfaSetupResponse(
        provisioning_uri=provisioning_uri,
        mfa_secret_for_testing=mfa_secret # WARNING: For testing only
    )

# --- Endpoints for Authentication (Login modified for MFA) ---
# ... (login and login/mfa/validate remain largely the same in structure but depend on UserInDB)
# No changes needed here for jti logic, as token creation is central.

# --- Logout Endpoint ---
@app.post("/logout")
@limiter.limit("20/minute")
async def logout(token_data: TokenData = Depends(get_current_user_data)): # Depends on new get_current_user_data
    if token_data.jti:
        token_blocklist.add(token_data.jti)
        print(f"Token JTI {token_data.jti} for user {token_data.username} added to blocklist.")
    else:
        # This case should ideally not be reached if get_current_user_data enforces jti
        print(f"Attempted to logout user {token_data.username} but JTI was missing in validated token data.")
        raise HTTPException(status_code=500, detail="Error processing logout: JTI missing after validation.")
    return {"message": "Successfully logged out"}


# --- Original Models (Modified for secured /chat) ---
    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA setup process not started. Please call /mfa/setup first.")
        
    if verify_totp(current_user.mfa_secret, request.totp_code):
        current_user.is_mfa_enabled = True
        # Again, in a real DB, save the user object.
        print(f"MFA successfully enabled for user: {current_user.username}")
        return {"message": "MFA enabled successfully."}
    else:
        raise HTTPException(status_code=400, detail="Invalid TOTP code.")

# --- Pydantic Models for MFA Login Flow ---
class LoginMfaRequiredResponse(BaseModel):
    mfa_required: bool = True
    username: str
    message: str = "MFA is enabled for this account. Please provide TOTP code via /login/mfa/validate."

class LoginMfaValidateRequest(BaseModel):
    username: str
    totp_code: str

# --- Endpoints for Authentication (Login modified for MFA) ---
@app.post("/login", response_model=Token | LoginMfaRequiredResponse)
@limiter.limit("10/minute") # Example: 10 login attempts per minute per IP
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = mock_user_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if user.is_mfa_enabled:
        if not user.mfa_secret: # Should not happen if is_mfa_enabled is true, but good check
            raise HTTPException(status_code=500, detail="MFA enabled but no secret found. Please contact support.")
        return LoginMfaRequiredResponse(username=user.username)
    
    # If MFA is not enabled, issue token directly
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

@app.post("/login/mfa/validate", response_model=Token)
@limiter.limit("5/minute") # Limit MFA validation attempts
async def login_mfa_validate(req: Request, request_data: LoginMfaValidateRequest): # Renamed request to req
    user = mock_user_db.get(request_data.username) # Use request_data
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or TOTP code.") # Avoid user enumeration
    
    if not user.is_mfa_enabled or not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA not enabled for this user or setup incomplete.")
        
    if verify_totp(user.mfa_secret, request_data.totp_code): # Use request_data
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        return Token(access_token=access_token, token_type="bearer")
    else:
        raise HTTPException(status_code=401, detail="Invalid username or TOTP code.")


# --- Original Models (Modified for secured /chat) ---
class ChatRequest(BaseModel):
    query: str = Field(
        ..., 
        min_length=1, 
        max_length=1000, 
        pattern=r"^[a-zA-Z0-9\s.,?!'-]+$",
        description="User query for the banking agent. Must be between 1 and 1000 characters and contain allowed characters."
    )

class ChatResponse(BaseModel):
    response: str
    user_name: str # Name of the user from vector DB
    user_id: str   # Username from token (used as user_id for vector DB)

# --- Secured /chat Endpoint ---
@app.post("/chat", response_model=ChatResponse)
@limiter.limit("60/minute") # Example: 60 chat requests per minute per IP, per authenticated user (if key changes)
async def chat_with_agent(req: Request, request_data: ChatRequest, current_active_user: UserInDB = Depends(get_current_active_user)): # Updated dependency
    """
    Handles a chat interaction with the banking agent.
    User is authenticated via JWT.
    """
    # The request_data.query has already been validated by Pydantic based on ChatRequest model
    
    # Conceptual: Further sanitization or query transformation could happen here.
    # For LLMs, primary defense is prompt engineering & how output is handled.
    # Example: simple check for disallowed keywords if any
    # if "some_forbidden_pattern" in request_data.query:
    #     raise HTTPException(status_code=400, detail="Invalid input pattern in query.")
    
    user_id_from_token = current_active_user.username # Use current_active_user.username
    print(f"Received chat request for authenticated user_id: {user_id_from_token} with validated query: '{request_data.query}'")

    # Get user details from the (mock) vector database using user_id_from_token
    details = get_user_data_from_vector_db(user_id_from_token, vector_db_client)

    if not details:
        # This case might mean the authenticated user doesn't have an entry in mock_vector_db_data
        # For now, we'll treat this as "user data not found" rather than an auth error.
        print(f"Data for User ID {user_id_from_token} not found in vector DB.")
        # Option 1: Raise 404 if user data in vector DB is essential
        raise HTTPException(status_code=404, detail=f"Banking details not found for user {user_id_from_token}")
        # Option 2: Proceed with a default name if some interaction is possible without full details
        # user_name_for_llm = user_id_from_token # Or some default
        # details = {} # Ensure details is an empty dict if not found
    
    user_name_for_llm = details.get("name", user_id_from_token) # Fallback to username if 'name' not in details

    history = [] # For now, conversation history is not maintained across API calls
    
    # Conceptual: Internal validation of the full prompt before sending to LLM.
    # E.g., check for accidental inclusion of overly sensitive template markers, etc.
    # final_prompt_to_llm = construct_llm_prompt(history, request_data.query, user_name_for_llm, details) # Assuming a helper
    # if not is_valid_for_llm(final_prompt_to_llm): # Assuming a helper
    #     raise HTTPException(status_code=500, detail="Internal prompt validation error.")

    print(f"Calling LLM for user '{user_name_for_llm}' (ID: {user_id_from_token}) with query: '{request_data.query}'")
    agent_response = ask_llm(history, request_data.query, user_name_for_llm, details)
    print(f"LLM response: '{agent_response}'")

    return ChatResponse(
        response=agent_response,
        user_name=user_name_for_llm,
        user_id=user_id_from_token
    )

@app.get("/")
@limiter.limit("100/minute") # General limit for root endpoint
async def root(request: Request):
    return {"message": "Welcome to the Personal Banking Agent API. Use the /docs endpoint for API details."}

if __name__ == "__main__":
    # Ensure OPENAI_API_KEY is set before trying to run, agent_module requires it.
    if "OPENAI_API_KEY" not in os.environ:
        print("WARNING: OPENAI_API_KEY environment variable not set. Using a dummy key for local Uvicorn run.")
        os.environ["OPENAI_API_KEY"] = "dummy_openai_key_for_uvicorn"
    
    # For Google credentials, the patch applied at import time should handle it for TextToSpeechClient.
    # If other Google clients were used directly, they might also need mocking or GOOGLE_APPLICATION_CREDENTIALS.

    print("Starting Uvicorn server for main_api...")
    uvicorn.run("main_api:app", host="0.0.0.0", port=8000, reload=True)
