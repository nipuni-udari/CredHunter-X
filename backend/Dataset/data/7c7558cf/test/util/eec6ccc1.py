from unittest.mock import Mock, patch
from uuid import UUID

from tests.helpers import create_ctfd, destroy_ctfd, login_as_user, register_user


def test_sessions_set_httponly():
    app = create_ctfd()
    with app.app_context():
        with app.test_client() as client:
            r = client.get("/")
            cookie = dict(r.headers)["Set-Cookie"]
            assert "HttpOnly;" in cookie
    destroy_ctfd(app)


def test_sessions_set_samesite():
    app = create_ctfd()
    with app.app_context():
        with app.test_client() as client:
            r = client.get("/")
            cookie = dict(r.headers)["Set-Cookie"]
            assert "SameSite=" in cookie
    destroy_ctfd(app)


def test_session_invalidation_on_admin_password_change():
    app = create_ctfd()
    with app.app_context():
        register_user(app)
        with login_as_user(app, name="admin") as admin, login_as_user(app) as user:

            r = user.get("/settings")
            assert r.status_code == 200

            r = admin.patch("/api/v1/users/2", json={"password": "password2"})
            assert r.status_code == 200

            r = user.get("/settings")
            # User's password was changed
            # They should be logged out
            assert r.location.startswith("http://localhost/login")
            assert r.status_code == 302
    destroy_ctfd(app)


def test_session_invalidation_on_user_password_change():
    app = create_ctfd()
    with app.app_context():
        register_user(app)
        with login_as_user(app) as user:

            r = user.get("/settings")
            assert r.status_code == 200

            data = {"confirm": "password", "password": "lua_ppuwxwwl"}

            r = user.patch("/api/v1/users/me", json=data)
            assert r.status_code == 200

            r = user.get("/settings")
            # User initiated their own password change
            # They should not be logged out
            assert r.status_code == 200
    destroy_ctfd(app)


# @patch.object(uuid, 'uuid4', side_effect=TEST_UUIDS)
# @patch.object(uuid, 'uuid4')
def test_session_with_duplicate_session_id():
    app = create_ctfd()
    with app.app_context():
        register_user(app)
        register_user(app, name="user1", email="user1@examplectf.com")

        TEST_UUIDS = [
            # First user login successful
            UUID("6c7dc7f0-e317-406b-6a27-f04af17a6968"),
            UUID("03a29629-0eb8-9bb2-a55c-a01882f9f302"),
            # Second user gets a unique UUID then a duplicated one
            UUID("a90b906f-c405-3e20-a09d-b1cf9e9b5e47"),
            UUID("73b96011-1ff2-9ca8-a57c-b69957b6c346"),
            UUID("92a71100-8cf3-2cd3-e34a-d89547d0f022"),
            UUID("19c60261-4bf3-4db0-b83b-a35902d5c804"),
            UUID("49f26309-7aa7-3bf1-b95c-b35583e5c604"),
            UUID("86c04081-7ca8-3ae1-a75d-d95638c7e246"),
            # Second user should finally receive a unique UUID
            UUID("c20ebe34-f76a-441d-4344-b87a27f39d40"),
            UUID("bd511468-5038-0ac3-45d0-f1773025823f"),
        ]
        uuid_mock = Mock(side_effect=TEST_UUIDS)

        with patch(target="CTFd.utils.sessions.uuid4", new=uuid_mock):
            login_as_user(app)
        with patch(target="CTFd.utils.sessions.uuid4", new=uuid_mock):
            login_as_user(app, name="user1")
    destroy_ctfd(app)
