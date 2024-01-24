from sqlalchemy import create_engine, Column, Integer, String, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE = "sqlite:///sqlite3.db"
NOTE_MAX_LENGTH = 10000


engine = create_engine(DATABASE)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()


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

Base.metadata.create_all(engine)


session.query(BannedIP).delete()
session.query(User).delete()
session.query(Note).delete()
session.commit()
