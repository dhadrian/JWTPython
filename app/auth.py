import logging
import os
import datetime
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from jwt import encode as jwt_encode, decode as jwt_decode, PyJWTError, ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load keys and other configurations from environment variables
JWT_SIGNING_KEY = os.getenv("JWT_SIGNING_KEY")
JWT_EXPECTED_AUDIENCE = os.getenv("JWT_EXPECTED_AUDIENCE")
JWT_EXPECTED_ISSUER = os.getenv("JWT_EXPECTED_ISSUER")

if not JWT_SIGNING_KEY:
    raise RuntimeError("JWT_SIGNING_KEY is not set or is empty.")

if not JWT_EXPECTED_AUDIENCE:
    raise RuntimeError("JWT_EXPECTED_AUDIENCE is not set or is empty.")

if not JWT_EXPECTED_ISSUER:
    raise RuntimeError("JWT_EXPECTED_ISSUER is not set or is empty.")

# FastAPI app setup
app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Function to create JWT token
def create_jwt_token(username: str):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # token expires in 1 hour

    # Define the payload (data inside the token)
    payload = {
        "sub": username,  # subject: username of the user
        "exp": expiration_time,  # expiration claim
        "aud": JWT_EXPECTED_AUDIENCE,
        "iss": JWT_EXPECTED_ISSUER,
    }

    # Encode the payload to create the JWT token
    token = jwt_encode(payload, JWT_SIGNING_KEY, algorithm="HS256")

    return token


# Dependency to verify JWT tokens in incoming requests
def verify_jwt_token(request: Request):
    auth_header = request.headers.get("Authorization")
    logger.debug(f"Authorization header: {auth_header}")

    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid or missing Authorization header")

    token = auth_header.split(" ")[1]

    try:
        decoded_token = jwt_decode(
            token,
            JWT_SIGNING_KEY,
            algorithms=["HS256"],
            audience=JWT_EXPECTED_AUDIENCE,
            issuer=JWT_EXPECTED_ISSUER,
        )
        return decoded_token

    except ExpiredSignatureError:
        logger.error("JWT has expired")
        raise HTTPException(status_code=401, detail="Token has expired")
    except InvalidAudienceError:
        logger.error("Invalid token audience")
        raise HTTPException(status_code=401, detail="Invalid token audience")
    except InvalidIssuerError:
        logger.error("Invalid token issuer")
        raise HTTPException(status_code=401, detail="Invalid token issuer")
    except PyJWTError as jwt_error:
        logger.error(f"JWT verification failed: {jwt_error}, token: {token[:10]}...{token[-10:]}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(jwt_error)}")
    except Exception as general_error:
        logger.error(f"Token verification error: {general_error}")
        raise HTTPException(status_code=500, detail=f"Token verification error: {str(general_error)}")



