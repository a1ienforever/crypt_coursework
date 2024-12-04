from datetime import datetime

from sqlalchemy import Column, String, Integer, ForeignKey, Boolean, DateTime
from sqlalchemy.cyextension.resultproxy import BaseRow
from sqlalchemy.orm import relationship

from app.database.base import Base


class User(Base):
    username = Column(String, unique=True, nullable=False)
    password = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    is_active = Column(Boolean, default=True)


    certificates = relationship("Certificate", back_populates="owner")
    keys = relationship("Key", back_populates="owner")

class Certificate(Base):
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    certificate_data = Column(String, nullable=False)
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now())
    valid_until = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="certificates")


class Token(Base):
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now())
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)

    user = relationship("User", back_populates="tokens")


class Key(Base):
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    key_type = Column(String, nullable=False)
    key_data = Column(String, nullable=False)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)

    owner = relationship("User", back_populates="keys")
