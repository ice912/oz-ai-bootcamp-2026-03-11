from fastapi import Depends, Body, HTTPException, status, APIRouter
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from auth.password import hash_password, verify_password
from auth.jwt import  create_access_token, verify_access_token, verify_user
from database.connection import get_session
from database.orm import User, HealthProfile
from request import SignUpRequest, LogInRequest, HealthProfileCreateRequest
from response import UserResponse, LogInResponse, HealthProfileResponse

router=APIRouter(tags=["User"])

@router.post("/users",
    summary="회원가입 API",
    status_code=status.HTTP_201_CREATED,
    response_model=UserResponse,)
async def signup_handler(
    body: SignUpRequest = Body(...),
    session = Depends(get_session),
):
# HealthProfile 중복 검사
    stmt = select(HealthProfile).where(HealthProfile.user_id == user_id)
    existing = await session.scalar(stmt)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="health profile already exists"
        )

# email 중복 검사
    stmt = select(User).where(User.email == body.email)
    user: User | None = await session.scalar(stmt)

    if user:
        raise HTTPException(status_code=409, detail="email already exists")

    # 새로운 유저 데이터 추가 & 비밀번호 해싱(hashing)
    new_user = User(
        email=body.email, 
        password_hash=hash_password(plain_password=body.password),
    )
    #새로운 유저 데이터 추가
    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)

    return new_user

@router.post(
    "/users/login",
    summary="로그인 API",
    status_code=status.HTTP_200_OK,
    response_model=LogInResponse
)
async def login_handler(
    body: LogInRequest = Body(...),
    session = Depends(get_session),
):
    stmt = select(User).where(User.email == body.email)
    user: User | None = await session.scalar(stmt)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="user not found")

    verified = verify_password(plain_password=body.password, password_hash=user.password_hash)

# 1. 'if' 문 뒤에 콜론(:) 추가
    if not verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")

    # [중요] return은 'if not verified'와 동일한 세로 라인에 있어야 합니다.
    # 사용자를 식별할 수 있는 JWT 발급
    access_token = create_access_token(user_id=user.id)
    return {"access_token": access_token}

#Path
#QueryParameter
#RequestBody
#Header

http_bearer = HTTPBearer()

@router.get("/test")
async def test_handler(
    auth_header: HTTPAuthorizationCredentials = Depends(http_bearer),
):
    # 1. 오타 수정: acess_token -> access_token
    access_token = auth_header.credentials
    
    # 2. 토큰 검증 및 페이로드 추출
    payload = verify_access_token(access_token)
    
    # 3. 검증 실패(None) 시 예외 처리 추가
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid or expired token"
        )
        
    return {"payload": payload}

@router.post(
    "/health-profiles",
    status_code=status.HTTP_201_CREATED,
    response_model=HealthProfileResponse,
)
async def create_health_profile_handler(
    user_id: int = Depends(verify_user),
    body: HealthProfileCreateRequest = Body(...),
    session = Depends(get_session),
):

    profile_data = body.model_dump()

    new_profile = HealthProfile(user_id=user_id, **profile_data)
    
    session.add(new_profile)
    await session.commit()
    await session.refresh(new_profile)
    return new_profile





