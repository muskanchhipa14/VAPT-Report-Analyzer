from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.services import user_service

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Handle plain-text comparison for existing users in SQLite database
    if plain_password == hashed_password:
        return True
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    payload = verify_access_token(token)
    if payload is None:
        raise credentials_exception
    email: str = payload.get("sub")
    if email is None:
        raise credentials_exception
    user = user_service.get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    return user

def get_current_user_optional(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if not token:
        return None
    payload = verify_access_token(token)
    if payload is None:
        return None
    email: str = payload.get("sub")
    if email is None:
        return None
    return user_service.get_user_by_email(db, email=email)


def require_source_code_access(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Enforces C-DAC Confidentiality Policy for source code assets.
    Only authorized roles (C-DAC Officers, Security Analysts, Auditors)
    are permitted to fetch, scan, view, or download source code repositories.
    Any attempt by unauthorized roles (e.g. 'user', 'viewer') is rejected with 403 Forbidden
    and recorded in the security audit log.
    """
    from app.core.roles import has_source_code_access, get_role_label
    from app.services.audit_helper import log_event

    user_role = getattr(current_user, "role", "user")
    if not has_source_code_access(user_role):
        log_event(
            db=db,
            user_name=current_user.name,
            action=f"Unauthorized Source Code Access Attempt ({get_role_label(user_role)})",
            module="Access Control",
            status="Denied"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access Denied: C-DAC Confidentiality Guidelines restrict source code access to authorized "
                f"Security Officers and Analysts. Role '{get_role_label(user_role)}' is denied access to fetch, scan, or view source code."
            )
        )

    return current_user

