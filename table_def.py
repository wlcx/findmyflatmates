import os
from sqlalchemy import create_engine, ForeignKey
from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref

engine = create_engine(os.environ['DATABASE_URL'], echo=True)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String)
    firstname = Column(String)
    lastname = Column(String)
    collegeid = Column(Integer, ForeignKey("colleges.id"))
    buildingid = Column(Integer, ForeignKey("buildings.id"))
    roomnumber = Column(Integer)
    pwhash = Column(String)
    biography = Column(String)
    facebookurl = Column(String)
    twitterurl = Column(String)
    unitnumber = Column(Integer)
    signup = Column(DateTime)
    subject = Column(String)

class College(Base):
    __tablename__ = "colleges"
    id = Column(Integer, primary_key=True)
    collegename = Column(String)
    users = relationship("User")
    buildings = relationship("Building")

class Building(Base):
    __tablename__ = "buildings"
    id = Column(Integer, primary_key=True)
    buildingcode = Column(String)
    buildingname = Column(String)
    collegeid = Column(Integer, ForeignKey("colleges.id"))
    buildingtype = Column(String)
    numunits = Column(Integer)
    users = relationship("User")
    numrooms = Column(Integer)

class VerificationLink(Base):
    __tablename__ = "verificationlinks"
    id = Column(Integer, primary_key=True)
    key = Column(String)
    username = Column(String)
    pwhash = Column(String)
    created = Column(DateTime)

Base.metadata.create_all(engine)
