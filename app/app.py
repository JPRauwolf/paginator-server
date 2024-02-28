from typing import Annotated
import secrets

from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyQuery, APIKeyHeader, APIKeyCookie

app = FastAPI()

security = HTTPBasic()

#TODO persistant api keys in dict (key -> list[users])
api_keys = ["1337"]

# todo read from env variable
ADMIN_USER = b"jp"
ADMIN_PASSWORD = b"password"

# cookie_key = APIKeyCookie(name="key", auto_error=False)
header_key = APIKeyHeader(name="x-api-key", auto_error=False)
query_key = APIKeyQuery(name="api-key", auto_error=False)


def get_api_key(
    # cookie_key: str = Security(cookie_key),
    _header_key: str = Depends(header_key),
    _query_key: str = Depends(query_key)
) -> str:

    # if cookie_key in api_keys:
    #    return cookie_key

    if _header_key in api_keys:
        return _header_key

    if _query_key in api_keys:
        return _query_key

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="api key missing or incorrect"
    )


def admin_auth(
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
    return name


@app.get("/api/generatekey")
def read_current_user(admin_name: Annotated[str, Depends(admin_auth)]):
    #TODO user keys
    new_key = "PN-" + secrets.token_urlsafe(16)
    api_keys.append(new_key)
    return {
        "api-key": new_key
        }


@app.get("/api/testkey")
def root(
    api_key: str = Depends(get_api_key)
):
    return {"api-key": api_key}
