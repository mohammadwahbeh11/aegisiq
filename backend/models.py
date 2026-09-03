from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.sql import func
from database import Base

class Log(Base):
    __tablename__ = "logs"
    
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, index=True)
    source_ip = Column(String, index=True)
    event_type = Column(String, index=True)
    severity = Column(String, index=True)
    raw_log = Column(Text)
    normalized_data = Column(JSON, nullable=True)
    # استخدام func.now() لجعل القاعدة هي المسؤولة عن تسجيل الوقت بدقة
    timestamp = Column(DateTime, server_default=func.now())

class Agent(Base):
    __tablename__ = "agents"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, unique=True, index=True)
    status = Column(String, default="active")

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, server_default=func.now())
    severity = Column(String, index=True)
    source_ip = Column(String, index=True)
    rule_name = Column(String, index=True)
    mitre_technique = Column(String, default="N/A")
    description = Column(Text)
    status = Column(String, default="New") # New, Resolved