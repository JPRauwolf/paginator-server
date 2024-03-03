from fastapi import status
from fastapi.testclient import TestClient

from app.app import app, admin_user
client = TestClient(app)


def test_user_create():
    url = "/api/users/add"
    # no api key
    response = client.post(url=url)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    # no data
    response = client.post(
        url=url,
        headers={"x-api-key": admin_user.user.key}
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # already exists
    response = client.post(
        url=url,
        headers={"x-api-key": admin_user.user.key},
        json={
            "name": admin_user.user.name
        }
    )
    assert response.status_code == status.HTTP_409_CONFLICT

    # created
    response = client.post(
        url=url,
        headers={"x-api-key": admin_user.user.key},
        json={
            "name": "test"
        }
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert not response.json()["detail"]["user"] is None
    user = response.json()["detail"]["user"]
    assert user["name"] == "test"
    assert not user["is_hidden"]
    assert not user["is_admin"]
