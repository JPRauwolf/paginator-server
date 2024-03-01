from pydantic import BaseModel


class ApiKey(BaseModel):
    api_key: str
    user: str
    is_admin: bool = False


# TODO add other stuff

class MessageData(BaseModel):
    text: str


class MessageBlob(BaseModel):
    info: str
    data: bytes


class Message(BaseModel):
    sender: str
    receiver: str
    data: MessageData | None = None
    data_blob: MessageBlob | None = None
