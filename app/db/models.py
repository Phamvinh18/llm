from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.sql import func
from app.db.base import Base
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(128), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(64), default='tester')
    is_active = Column(Boolean, default=True)
class Finding(Base):
    __tablename__ = 'findings'
    id = Column(Integer, primary_key=True)
    title = Column(String(256))
    risk = Column(String(64))
    url = Column(String(1024))
    parameter = Column(String(256))
    evidence = Column(Text)
    owasp_ref = Column(String(64))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
