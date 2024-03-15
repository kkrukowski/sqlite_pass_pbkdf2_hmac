import sqlite3
import bcrypt
from hashlib import pbkdf2_hmac
import os
from dotenv import load_dotenv

load_dotenv()

SALT_SIZE = 16

# Get database name from .env
db_name = os.environ.get('DB_NAME')

# Get hashing interations number
HASH_ITERS = int(os.environ.get("HASH_ITERS"))


def init_database():
    """Initialize database tables"""
    con = sqlite3.connect(db_name)
    cursor = con.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash string NOT NULL,
            salt string NOT NULL
        )
    """)

    con.commit()
    con.close()


def get_password() -> bool:
    password = input("Enter password: ")
    repassword = input("Re-enter password: ")

    if password != repassword:
        raise ValueError("Passwords are different!")

    if len(password) == 0:
        raise ValueError("Password cannot be empty!")

    # If passwords are valid then add password to db
    add_password(password)

    return True


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    verify_password_hash = pbkdf2_hmac("sha256", password.encode(), salt.encode(), HASH_ITERS)
    return verify_password_hash.hex() == password_hash


def add_password(password: str) -> bool:
    """Add hashed password to sqlite database"""
    if len(password) is 0:
        raise ValueError("Password cannot be empty!")

    salt = os.urandom(SALT_SIZE)
    password_hash = pbkdf2_hmac("sha256", password.encode(), salt.hex().encode(), HASH_ITERS)

    if not verify_password(password, password_hash.hex(), salt.hex()):
        raise ValueError("Password hash is not valid!")

    con = sqlite3.connect(db_name)
    cursor = con.cursor()

    cursor.execute("""
        INSERT INTO passwords (password_hash, salt)
        VALUES (?, ?)
    """, (password_hash.hex(), salt.hex()))

    con.commit()
    con.close()

    print("Password has been added correctly!")
    return True


if __name__ == '__main__':
    # Create tables if not exists
    init_database()

    # Get password
    get_password()
