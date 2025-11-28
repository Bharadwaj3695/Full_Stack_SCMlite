from fastapi import APIRouter, Form, HTTPException, Depends, status
from typing import Dict, Any, Optional
import hashlib
import re
import os
from datetime import datetime, timedelta

from jose import jwt
from jose.exceptions import JWTError
from fastapi.security import OAuth2PasswordBearer

from backend.app import get_collections

router = APIRouter(prefix="/api/users", tags=["users"])

# ==========================
# JWT CONFIG
# ==========================
# In production, keep this in .env and load with os.getenv
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/users/login")


# ==========================
# Helper functions
# ==========================

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def validate_email(email: str) -> bool:
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def validate_password(password: str) -> bool:
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# ==========================
# SIGNUP
# ==========================

@router.post("/signup")
def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    username = username.strip()
    email_l = email.strip().lower()

    if not validate_email(email_l):
        raise HTTPException(status_code=400, detail="Invalid email format")
    if not validate_password(password):
        raise HTTPException(
            status_code=400,
            detail="Weak password. Requirements: >=8 chars, uppercase, lowercase, number, special char.",
        )
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    cols = get_collections()
    users_col = cols["users"]

    existing = users_col.find_one({"$or": [{"username": username}, {"email": email_l}]})
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    hashed = hash_password(password)
    users_col.insert_one({"username": username, "email": email_l, "password": hashed})

    return {"message": f"User {username} signed up successfully"}


# ==========================
# LOGIN → returns JWT
# ==========================

@router.post("/login")
def login(
    identifier: str = Form(...),  # username or email
    password: str = Form(...),
):
    ident = identifier.strip()
    ident_email = ident.lower()

    cols = get_collections()
    users_col = cols["users"]

    user = users_col.find_one({"$or": [{"username": ident}, {"email": ident_email}]})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    stored_hash = user.get("password")
    if stored_hash != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Create JWT token
    access_token = create_access_token(
        data={"sub": user["username"], "email": user["email"]}
    )

    # Don't expose password or _id
    user_safe = {k: v for k, v in user.items() if k not in ("password", "_id")}

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_safe,
        "message": "Login successful",
    }


# ==========================
# DEPENDENCY: CURRENT USER
# ==========================

def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    cols = get_collections()
    users_col = cols["users"]
    user = users_col.find_one({"username": username})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # strip sensitive fields
    return {k: v for k, v in user.items() if k not in ("password",)}


# ==========================
# PROTECTED ROUTE EXAMPLE
# ==========================

@router.get("/me")
def read_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Example protected endpoint.
    Requires Authorization: Bearer <token>
    """
    return {"user": current_user}
