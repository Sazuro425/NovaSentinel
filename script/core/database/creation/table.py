#!/usr/bin/env python3
from sqlalchemy import (
    Column, String, Integer,
    ForeignKey, UniqueConstraint,
    ForeignKeyConstraint,event)

from sqlalchemy.orm import relationship
from script.core.database.creation.create_database import Base, engine
from script.core.log.mylog import get_custom_logger

logger = get_custom_logger("database")

class Host(Base):
    __tablename__ = "hosts"
    IP        = Column(String(15), primary_key=True)
    dns_name  = Column(String(255), nullable=True)
    GW        = Column(String(15), nullable=False)
    INTERFACE = Column(String(255), nullable=False)
    DNS       = Column(String(15), nullable=False)

    open_ports   = relationship("OpenPort",    back_populates="host", cascade="all, delete-orphan")
    applications = relationship("Application", back_populates="host", cascade="all, delete-orphan")

    @classmethod
    def __declare_last__(cls):
        # ce hook est appelé une fois que la table est configurée
        event.listen(cls, 'after_insert',
                     lambda mapper, conn, target: 
                         logger.info(f"Host créé : {target.IP}"))
        event.listen(cls, 'after_update',
                     lambda mapper, conn, target: 
                         logger.info(f"Host mis à jour : {target.IP}"))
        event.listen(cls, 'after_delete',
                     lambda mapper, conn, target: 
                         logger.info(f"Host supprimé : {target.IP}"))

class OpenPort(Base):
    __tablename__ = "open_ports"
    id      = Column(Integer, primary_key=True, autoincrement=True)
    host_ip = Column(String(15), ForeignKey("hosts.IP",
                       ondelete="CASCADE", onupdate="CASCADE"), nullable=False)
    port    = Column(Integer, nullable=False)

    __table_args__ = (
        UniqueConstraint("host_ip", "port", name="host_port_unique"),
    )

    host = relationship("Host", back_populates="open_ports")

    @classmethod
    def __declare_last__(cls):
        event.listen(cls, 'after_insert',
                     lambda m, c, t: logger.info(f"Port ouvert ajouté : {t.host_ip}:{t.port}"))
        event.listen(cls, 'after_delete',
                     lambda m, c, t: logger.info(f"Port ouvert supprimé : {t.host_ip}:{t.port}"))
class local(Base):
    __tablename__ = "local"
    ip            = Column(String(15), primary_key=True)
    mac           = Column(String(17), nullable=False)
    dhcp          = Column(String(15), nullable=False)
    dns           = Column(String(15), nullable=False)
    interface     = Column(String(20), nullable=False)
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

    @classmethod
    def __declare_last__(cls):
        event.listen(cls, 'after_insert',
                     lambda m, c, t: logger.info(
                         f"Application '{t.application_name}' ajoutée sur {t.host_ip}:{t.application_port}"
                     ))
        event.listen(cls, 'after_delete',
                     lambda m, c, t: logger.info(
                         f"Application '{t.application_name}' supprimée de {t.host_ip}:{t.application_port}"
                     ))
def createtable(Base, engine):
    for tbl in Base.metadata.sorted_tables:
        event.listen(tbl, 'after_create',
                     lambda t, conn, **kw: logger.info(f"Table créée : {t.name}"))
        event.listen(tbl, 'after_drop',
                     lambda t, conn, **kw: logger.info(f"Table supprimée : {t.name}"))

    try:
        logger.info("Démarrage create_all() …")
        Base.metadata.create_all(engine)
        logger.info("create_all() OK")
    except Exception as e:
        logger.error(f"Erreur create_all() : {e}", exc_info=True)