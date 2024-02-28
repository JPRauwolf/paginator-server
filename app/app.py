from typing import Annotated
import secrets

from pydantic import BaseModel
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyQuery, APIKeyHeader

app = FastAPI()
security = HTTPBasic()

# TODO keylists to file
user_api_keys = {}
admin_api_keys = ["1337"]

# todo read from env variable
ADMIN_USER = b"jp"
ADMIN_PASSWORD = b"password"

header_key = APIKeyHeader(name="x-api-key", auto_error=False)
query_key = APIKeyQuery(name="api-key", auto_error=False)


class ApiKey(BaseModel):
    api_key: str
    user: str
    is_admin: bool = False


def get_api_key(
    _header_key: str = Depends(header_key),
    _query_key: str = Depends(query_key)
) -> ApiKey:
    if _header_key:
        if _header_key in admin_api_keys:
            return ApiKey(
                api_key=_header_key,
                user="admin",
                is_admin=True
            )
        if _header_key in user_api_keys.keys():
            return ApiKey(
                api_key=_header_key,
                user=user_api_keys[_header_key]
            )

    if _query_key:
        if _query_key in admin_api_keys:
            return ApiKey(
                api_key=_query_key,
                user="admin",
                is_admin=True
            )

        if _query_key in user_api_keys.keys():
            return ApiKey(
                api_key=_query_key,
                user=user_api_keys[_query_key]
            )

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


@app.get("/api/keys/add/user")
def add_user_api_key(user_name: str, admin_name: Annotated[str, Depends(admin_auth)]):
    new_key = "PN-" + secrets.token_urlsafe(16)
    user_api_keys[new_key] = user_name
    return {
        "status": "success",
        "details": "created new user api key",
        "api-key": {
            "user": user_name,
            "key": new_key
        }
    }


@app.get("/api/keys/add/admin")
def add_admin_api_key(admin_name: Annotated[str, Depends(admin_auth)]):
    new_key = "PN-" + secrets.token_urlsafe(16)
    admin_api_keys.append(new_key)
    return {
        "status": "success",
        "details": "created new admin api key",
        "api-key": {
            "user": "admin",
            "key": new_key
        }
    }


@app.get("/api/keys/show")
def show_all_api_keys(
    api_key: Annotated[ApiKey, Depends(get_api_key)]
):
    if not api_key.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="this api key doesnt permit you to see the requested keys"
        )
    users = set([u for u in user_api_keys.values()])
    ud = {}
    for  in users:
        if ud[user]:
            ud[user].append(user_api_keys)
    return {
        "admin-keys": admin_api_keys,
        "user-keys":
    }
    
@app.get("/api/keys/show/{user}")
def show_user_api_key(
    user: str,
    api_key: Annotated[ApiKey, Depends(get_api_key)]
):
    if not (api_key.is_admin or api_key.user == user):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="this api key doesnt permit you to see the requested keys"
        )
    return {
        "user-keys": {
            user :
            [key for u, key in user_api_keys.items() if u == user]
        }
    }

