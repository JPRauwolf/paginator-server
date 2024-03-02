from queue import SimpleQueue, Empty
from pydantic import BaseModel


# TODO add other stuff

class MessageData(BaseModel):
    text: str


class MessageBlob(BaseModel):
    info: str
    data: bytes


class Message(BaseModel):
    sender: str
    data: MessageData | None = None
    data_blob: MessageBlob | None = None


class User(BaseModel):
    key: str
    name: str
    is_admin: bool = False
    is_hidden: bool = False

    def __eq__(self, other):
        return self.name == other.name


class CreateUser(BaseModel):
    name: str
    is_admin: bool = False
    is_hidden: bool = False

    def to_user(self, key: str) -> User:
        return User(
            name=self.name,
            is_admin=self.is_admin,
            is_hidden=self.is_hidden,
            key=key
        )


class QueueUser():
    user: User
    queue: SimpleQueue[Message] = SimpleQueue()

    def __init__(self, user: User):
        self.user = user

    def __eq__(self, other):
        return self.user == other.user

    def queue_message(self, message: Message):
        self.queue.put(message)

    def unqueue_message(self) -> Message | None:
        try:
            return self.queue.get_nowait()
        except Exception:
            return None
