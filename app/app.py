from typing import Annotated
import secrets

from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyQuery, APIKeyHeader, APIKeyCookie

app = FastAPI()

security = HTTPBasic()

api_keys = ["1337"]

# todo read from env variable
ADMIN_USER = b"jp"
ADMIN_PASSWORD = b"password"

# cookie_key = APIKeyCookie(name="key", auto_error=False)
header_key = APIKeyHeader(name="x-api-key", auto_error=False)
query_key = APIKeyQuery(name="api-key", auto_error=False)


def get_api_key(
    # cookie_key: str = Security(cookie_key),
    header_key: str = Security(header_key),
    query_key: str = Security(query_key)
) -> str:

    # if cookie_key in api_keys:
    #    return cookie_key

    if header_key in api_keys:
        return header_key

    if query_key in api_keys:
        return query_key
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="api key missing or incorrect"
    )


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
            headers={"WWW-Authenticate": "Basic"}
        )
    return credentials.username


@app.get("/api/generatekey")
def read_current_user(username: Annotated[HTTPBasicCredentials, Depends(passwd_auth)]):
    return {"username": username}


@app.get("/")
def root(
    api_key: str = Depends(get_api_key)
):
    return {"api-key": api_key}
