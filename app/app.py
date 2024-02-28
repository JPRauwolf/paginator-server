from typing import Annotated
import secrets

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyQuery, APIKeyHeader

app = FastAPI()

security = HTTPBasic()

api_keys = ["1337"]

#todo read from env variable
admin_user = b"jp"
admin_password = b"password"

def authentificate_user(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)]
):
    user_name_bytes = credentials.username.encode("utf8")
    user_name_right = secrets.compare_digest(user_name_bytes, b"jp")
    password_bytes = credentials.password.encode("utf8")
    password_right = secrets.compare_digest(password_bytes, b"password")
    if not (password_right and user_name_right):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="wrong username or password",
            headers={"WWW-Authenticate" : "Basic"}
        )
    return credentials.username
    

@app.get("/api/generatekey")
def read_current_user(username: Annotated[HTTPBasicCredentials, Depends(authentificate_user)]):
    return {"username": username}


