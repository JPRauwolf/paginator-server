from typing import Annotated
import secrets

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyQuery, APIKeyHeader

app = FastAPI()

security = HTTPBasic()

api_keys = ["1337"]

#todo read from env variable
ADMIN_USER = b"jp"
ADMIN_PASSWORD = b"password"

def passwd_auth(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)]
):
    name = credentials.username.encode("utf8")
    passwd = credentials.password.encode("utf8")
    user_name_right = secrets.compare_digest(name, ADMIN_USER)
    password_right = secrets.compare_digest(passwd, ADMIN_PASSWORD)
    if not (password_right and user_name_right):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="wrong username or password",
            headers={"WWW-Authenticate" : "Basic"}
        )
    return credentials.username
    

@app.get("/api/generatekey")
def read_current_user(username: Annotated[HTTPBasicCredentials, Depends(passwd_auth)]):
    return {"username": username}


