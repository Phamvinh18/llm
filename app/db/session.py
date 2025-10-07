import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
DATABASE_URL = os.getenv('DATABASE_URL','sqlite:///./app/data/vawebsec.db')
engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

def init_db():
    from app.db.base import Base
    Base.metadata.create_all(bind=engine)
