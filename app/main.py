import logging
from fastapi import FastAPI, HTTPException, Depends

import os
from .auth import verify_jwt_token,create_jwt_token
from .model import UserLogin
import nest_asyncio

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

nest_asyncio.apply()
app = FastAPI()

JWT_USERNAME = os.getenv("JWT_USERNAME")
JWT_PASSWORD = os.getenv("JWT_PASSWORD")

# Example route to protect
@app.get("/protected")
async def protected_route(decoded_token: dict = Depends(verify_jwt_token)):
    return {"message": "You are authorized", "user": decoded_token["sub"]}

# Token generation route
@app.post("/token")
async def login_for_access_token(username: str, password: str):
    # In a real app, validate the username and password
    if username == JWT_USERNAME and password == JWT_PASSWORD:
        token = create_jwt_token(username)
        return {"access_token": token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=400, detail="Invalid credentials")
