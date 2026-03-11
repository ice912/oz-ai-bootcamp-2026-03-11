import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from config import settings

http_bearer = HTTPBearer()

def create_access_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.now(timezone.utc) + timedelta(hours=24)
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")

def verify_access_token(access_token: str) -> dict | None:
    try:
        # algorithms 오타 수정 및 디코딩
        payload = jwt.decode(access_token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        return payload
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        return None

def verify_user(
    auth_header: HTTPAuthorizationCredentials = Depends(http_bearer)
) -> int:
    access_token = auth_header.credentials
    payload = verify_access_token(access_token)
    
    if not payload or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid or expired token"
        )
    return int(payload.get("sub"))

