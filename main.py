from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import User
from schemas import UserCreate, Token
from auth import hash_password, verify_password, create_token
from database import Base
from fastapi.security import OAuth2PasswordRequestForm
from auth import get_current_user

app = FastAPI(title="User Auth API")

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        email=user.email,
        password=hash_password(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message":"User registered successfully"}



@app.post("/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == form_data.username).first()

    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(user.email)

    return {
        "access_token": token,
        "token_type": "bearer"
    }


@app.get("/me")
def read_me(current_user: str = Depends(get_current_user)):
    return {
        "email": current_user,
        "message": "You are authorized 🎉"
    }