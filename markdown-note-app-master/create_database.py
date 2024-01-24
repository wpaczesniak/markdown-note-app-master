
# import sqlite3

# DATABASE = "./sqlite3.db"
# NOTE_MAX_LENGTH = 10000


# print("[*] Init database!")
# db = sqlite3.connect(DATABASE)
# sql = db.cursor()
# sql.execute("DROP TABLE IF EXISTS banned_ips;")
# sql.execute(
#     "CREATE TABLE banned_ips (ip_address VARCHAR(16), failed_login_streak INTEGER NOT NULL, banned_until timestamp );")
# sql.execute("DELETE FROM banned_ips;")
# sql.execute("DROP TABLE IF EXISTS user;")
# sql.execute(
#     "CREATE TABLE user (username VARCHAR(32), password VARCHAR(128));")
# sql.execute("DELETE FROM user;")

# sql.execute("DROP TABLE IF EXISTS notes;")
# sql.execute(
#     f"CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), title VARCHAR(32), note VARCHAR({NOTE_MAX_LENGTH}), public INTEGER NOT NULL, password_hash VARCHAR(128), AES_salt VARCHAR(25), init_vector VARCHAR(25));")
# sql.execute("DELETE FROM notes;")
# db.commit()

from sqlalchemy import create_engine, Column, Integer, String, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE = "sqlite:///sqlite3.db"
NOTE_MAX_LENGTH = 10000

# Inicjalizacja bazy danych
engine = create_engine(DATABASE)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

# Definicja tabel w bazie danych
class BannedIP(Base):
    __tablename__ = 'banned_ips'

    ip_address = Column(String(16), primary_key=True)
    failed_login_streak = Column(Integer, nullable=False)
    banned_until = Column(TIMESTAMP)

class User(Base):
    __tablename__ = 'user'

    username = Column(String(32), primary_key=True)
    password = Column(String(128))

class Note(Base):
    __tablename__ = 'notes'

    id = Column(Integer, primary_key=True)
    username = Column(String(32))
    title = Column(String(32))
    note = Column(String(NOTE_MAX_LENGTH))
    public = Column(Integer, nullable=False)
    password_hash = Column(String(128))
    AES_salt = Column(String(25))
    init_vector = Column(String(25))

# Tworzenie tabel w bazie danych
Base.metadata.create_all(engine)

# Czyszczenie tabel
session.query(BannedIP).delete()
session.query(User).delete()
session.query(Note).delete()
session.commit()
