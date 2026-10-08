import os
from unittest import mock

from django.http import HttpResponse
from django.test import TestCase, Client, RequestFactory, SimpleTestCase
from django.contrib.auth.models import User
from datetime import datetime
from server.models import Computer, Secret, Request


class RequestProcess(TestCase):
    def test_request_passes_correct_data_to_template(self):
        admin = User.objects.create_superuser("admin", "a@a.com", "sekrit")
        tech = User.objects.create_user("tech", "a@a.com", "password")
        tech.save()
        tech_test_computer = Computer(
            serial="TECHSERIAL", username="Daft Tech", computername="compy587"
        )
        tech_test_computer.save()
        test_secret = Secret(
            computer=tech_test_computer,
            secret="SHHH-DONT-TELL",
            date_escrowed=datetime.now(),
        )
        test_secret.save()
        secret_request = Request(secret=test_secret, requesting_user=tech)
        secret_request.save()
        client = Client()
        login_response = self.client.post(
            "/login/", {"username": "admin", "password": "sekrit"}, follow=True
        )
        response = self.client.get("/manage-requests/", follow=True)
        print(response)
        self.assertTrue(response.context["user"].is_authenticated)


class APIKeyRotation(SimpleTestCase):
    """The middleware accepts the current key, and the previous one while it is set."""

    def _middleware(self, **env):
        from server.middleware import APIKeyAuthMiddleware

        with mock.patch.dict(os.environ, env, clear=False):
            for name in ("CRYPT_API_KEY", "CRYPT_API_KEY_PREVIOUS"):
                if name not in env:
                    os.environ.pop(name, None)
            return APIKeyAuthMiddleware(lambda request: HttpResponse("ok"))

    def _status(self, middleware, key):
        request = RequestFactory().get("/verify/SERIAL/recovery_key/")
        if key is not None:
            request.META["HTTP_X_API_KEY"] = key
        return middleware(request).status_code

    def test_current_key_only(self):
        mw = self._middleware(CRYPT_API_KEY="new-key")
        self.assertEqual(self._status(mw, "new-key"), 200)
        self.assertEqual(self._status(mw, "old-key"), 403)
        self.assertEqual(self._status(mw, None), 401)

    def test_previous_key_accepted_during_rotation(self):
        mw = self._middleware(CRYPT_API_KEY="new-key", CRYPT_API_KEY_PREVIOUS="old-key")
        self.assertEqual(self._status(mw, "new-key"), 200)
        self.assertEqual(self._status(mw, "old-key"), 200)
        self.assertEqual(self._status(mw, "other-key"), 403)

    def test_blank_previous_key_is_ignored(self):
        mw = self._middleware(CRYPT_API_KEY="new-key", CRYPT_API_KEY_PREVIOUS="  ")
        self.assertIsNone(mw.previous_api_key)
        self.assertEqual(self._status(mw, ""), 401)

    def test_previous_key_alone_does_not_enable_auth(self):
        mw = self._middleware(CRYPT_API_KEY_PREVIOUS="old-key")
        self.assertIsNone(mw.api_key)
        self.assertEqual(self._status(mw, None), 200)
