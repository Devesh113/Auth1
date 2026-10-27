import unittest

from auth import AuthService, hash_password, verify_password


class AuthTests(unittest.TestCase):
    def test_signup_hashes_password(self) -> None:
        service = AuthService()
        user = service.signup("alice", "super-secret")
        self.assertNotEqual(user.password_hash, "super-secret")
        self.assertTrue(verify_password("super-secret", user.password_hash))

    def test_login_success_and_failure(self) -> None:
        service = AuthService()
        service.signup("alice", "super-secret")

        self.assertTrue(service.login("alice", "super-secret"))
        self.assertFalse(service.login("alice", "wrong-password"))
        self.assertFalse(service.login("unknown-user", "super-secret"))

    def test_duplicate_username_is_rejected(self) -> None:
        service = AuthService()
        service.signup("alice", "secret")
        with self.assertRaises(ValueError):
            service.signup("alice", "secret2")

    def test_empty_values_are_rejected(self) -> None:
        service = AuthService()
        with self.assertRaises(ValueError):
            service.signup("", "secret")
        with self.assertRaises(ValueError):
            service.signup("alice", "")

    def test_hash_round_trip(self) -> None:
        hashed = hash_password("abc123")
        self.assertTrue(verify_password("abc123", hashed))
        self.assertFalse(verify_password("def456", hashed))


if __name__ == "__main__":
    unittest.main()
