from typing import Annotated
import secrets

import yaml

from fastapi import FastAPI, Depends, HTTPException, status, Response
from fastapi.security import APIKeyHeader

from models import Message, MessageBlob, MessageData, User, QueueUser, CreateUser

# TODO read from env variable

'''
ADMIN_USER = b"admin"
ADMIN_TOKEN = b"1337"

admin_user = QueueUser(
    User(
        name=ADMIN_USER,
        hidden=True,
        key=ADMIN_TOKEN,
        is_admin=True
    )
)
'''

app = FastAPI()
qusers: dict[str, QueueUser] = {}#= {admin_user.user.name: admin_user}

header_key = APIKeyHeader(name="x-api-key", auto_error=False)

def add_user_from_file():
    with open('/etc/paginator/config/users.yaml', 'r') as f:
        y = yaml.safe_load(f)
        for user in y:
            if (user['user']):
                u = user['user']
                q = QueueUser(User(
                    name=u['name'],
                    key=u['key'],
                    is_hidden=u['is_hidden'],
                    is_admin=u['is_admin']
                ))
                qusers[u['name']] = q

add_user_from_file()

def user_auth(
    _header_key: str = Depends(header_key)
) -> QueueUser:
    if _header_key:
        for _, user in qusers.items():
            if secrets.compare_digest(user.user.key.encode("utf8"), _header_key.encode("utf8")):
                return user
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="api key missing or incorrect"
    )


def admin_auth(
    quser: QueueUser = Depends(user_auth)
) -> QueueUser:
    if quser.user.is_admin:
        return quser

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="you are not permitted to do this operation"
    )


def generate_key() -> str:
    return "PN-" + secrets.token_urlsafe(16)


@app.post("/api/users/add", status_code=status.HTTP_201_CREATED)
def add_user_key(
    cuser: CreateUser,
    admin_quser: Annotated[QueueUser, Depends(admin_auth)]
):
    if cuser.name in qusers:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )
    quser = QueueUser(
        cuser.to_user(generate_key())
    )
    qusers[quser.user] = quser
    return {
        "status": "success",
        "detail": quser
    }


@app.get("/api/users/refreshkey")
def refresh_api_key(
    quser: Annotated[QueueUser, Depends(user_auth)]
):
    qusers[quser.user.name].user.key = generate_key()
    return {
        "status": "success",
        "detail": qusers[quser.user.name]
    }


@app.get("/api/users/refreshkey/{user}")
def refresh_other_api_key(
    user: str,
    admin_quser: Annotated[QueueUser, Depends(admin_auth)]
):
    if user not in qusers:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="the requested user does not exist"
        )
    qusers[user].user.key = generate_key()
    return {
        "status": "success",
        "detail": qusers[user]
    }


@app.get("/api/users/show")
async def show_users(
    quser: Annotated[QueueUser, Depends(user_auth)]
):
    if quser.user.is_admin:
        u_list = list(qusers.keys())
    else:
        u_list = [u.user.name for u in qusers.values() if not u.user.is_hidden]
    return {
        "users": u_list
    }


@app.get("/api/users/detail/{user}")
async def show_user_detail(
    user: str,
    asking_quser: Annotated[QueueUser, Depends(user_auth)]
):
    if not (asking_quser.user.is_admin or asking_quser.user.name == user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="you are not permitted to do this operation"
        )
    if user not in qusers:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="user does not exist"
        )
    return qusers[user]


@app.get("/api/messages/get/", status_code=status.HTTP_200_OK)
def get_messages_user(
    user: Annotated[QueueUser, Depends(user_auth)],
    response: Response
):
    message = user.unqueue_message()
    if message is None:
        response.status_code = status.HTTP_204_NO_CONTENT
    return {
        "message": message
    }


@app.post("/api/messages/queue/plain", status_code=status.HTTP_201_CREATED)
def create_message_plain(
    data: MessageData,
    receiver: str,
    quser: Annotated[QueueUser, Depends(user_auth)]
):
    if receiver not in qusers:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no user with the name {receiver} exists"
        )
    message = Message(
        sender=quser.user.name,
        data=data
    )
    qusers[receiver].queue_message(message)
    return {
        "message": message
    }


@app.post("/api/messages/queue/blob", status_code=status.HTTP_201_CREATED)
def create_message_blob(
    data: MessageBlob,
    receiver: str,
    quser: Annotated[QueueUser, Depends(user_auth)]
):
    if receiver not in qusers:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no user with the name {receiver} exists"
        )
    message = Message(
        sender=quser.user.name,
        data_blob=data
    )
    qusers[receiver].queue_message(message)
    return {
        "message": message
    }
