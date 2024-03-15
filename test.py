import unittest
from unittest.mock import patch, MagicMock
from main import get_password
from main import verify_password
from main import add_password


class GetPassword(unittest.TestCase):
    @patch('builtins.input', side_effect=["password", "password"])
    def test_get_password_valid(self, mock_input):
        self.assertTrue(get_password())

    @patch('builtins.input', side_effect=["password", "diff_password"])
    def test_get_password_different(self, mock_input):
        with self.assertRaises(ValueError):
            get_password()

    @patch('builtins.input', side_effect=["", ""])
    def test_get_password_empty(self, mock_input):
        with self.assertRaises(ValueError):
            get_password()


class VerifyPassword(unittest.TestCase):
    def test_verify_password_valid(self):
        password = '1234'
        salt = '61a616cbf1276b0e9e2650d350a6a50d'
        password_hash = '879332218c53be1728479ac5a6aad12223a58e106b057110472a7807582fa564'
        self.assertTrue(verify_password(password, password_hash, salt))

    def test_verify_password_invalid_hash(self):
        password = '1234'
        salt = '61a616cbf1276b0e9e2650d350a6a50d'
        password_hash = 'invalid_hash'
        self.assertFalse(verify_password(password, password_hash, salt))

    def test_verify_password_different_salt(self):
        password = '1234'
        salt = 'different_salt'
        password_hash = '879332218c53be1728479ac5a6aad12223a58e106b057110472a7807582fa564'
        self.assertFalse(verify_password(password, password_hash, salt))

    def test_verify_password_different_password(self):
        password = 'different_password'
        salt = '61a616cbf1276b0e9e2650d350a6a50d'
        password_hash = '879332218c53be1728479ac5a6aad12223a58e106b057110472a7807582fa564'
        self.assertFalse(verify_password(password, password_hash, salt))


class AddPassword(unittest.TestCase):
    def test_add_password_valid(self):
        password = "valid_password"
        self.assertTrue(add_password(password))

    def test_add_password_empty(self):
        password = ''
        with self.assertRaises(ValueError):
            add_password(password)


if __name__ == '__main__':
    unittest.main()
