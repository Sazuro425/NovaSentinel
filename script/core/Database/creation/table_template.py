#!/usr/bin/env python3
from sqlalchemy import (
    Column, String, Integer,
    ForeignKey, UniqueConstraint,
    ForeignKeyConstraint
)
from sqlalchemy.orm import relationship

# importe Base et engine partagés
from create_database import Base, engine

class Host(Base):
    __tablename__ = "hosts"
    IP        = Column(String(15), primary_key=True)
    dns_name  = Column(String(255), nullable=True)
    GW        = Column(String(15), nullable=False)
    INTERFACE = Column(String(255), nullable=False)
    DNS       = Column(String(15), nullable=False)

    open_ports   = relationship("OpenPort",    back_populates="host", cascade="all, delete-orphan")
    applications = relationship("Application", back_populates="host", cascade="all, delete-orphan")


class OpenPort(Base):
    __tablename__ = "open_ports"
    id      = Column(Integer, primary_key=True, autoincrement=True)
    host_ip = Column(String(15), ForeignKey("hosts.IP", ondelete="CASCADE", onupdate="CASCADE"), nullable=False)
    port    = Column(Integer, nullable=False)

    __table_args__ = (
        UniqueConstraint("host_ip", "port", name="host_port_unique"),
    )

    host = relationship("Host", back_populates="open_ports")


class Application(Base):
    __tablename__ = "application"
    id                  = Column(Integer, primary_key=True, autoincrement=True)
    host_ip             = Column(String(15), nullable=False)
    application_name    = Column(String(50), nullable=False)
    application_version = Column(String(50), nullable=False)
    application_port    = Column(Integer, nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["host_ip"], ["hosts.IP"],
            ondelete="CASCADE", onupdate="CASCADE"
        ),
        ForeignKeyConstraint(
            ["host_ip", "application_port"],
            ["open_ports.host_ip", "open_ports.port"],
            ondelete="CASCADE", onupdate="CASCADE"
        ),
    )

    host = relationship("Host", back_populates="applications")
    port = relationship(
        "OpenPort",
        primaryjoin="and_(Application.host_ip==OpenPort.host_ip,"
                    "Application.application_port==OpenPort.port)",
        viewonly=True
    )

Base.metadata.create_all(engine)
