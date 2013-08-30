import os
from sqlalchemy import create_engine, ForeignKey
from sqlalchemy import Column, Date, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref

engine = create_engine(os.environ['DATABASE_URL', echo=True)
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
	flat = Column(Integer)

	def __init__(self, username, firstname, lastname, collegeid, buildingid, 
				roomnumber, pwhash, biography, facebookurl, flat):
		self.username = username
		self.firstname = firstname
		self.lastname = lastname
		self.collegeid = collegeid
		self.buildingid = buildingid
		self.roomnumber = roomnumber
		self.pwhash = pwhash
		self.biography = biography
		self.facebookurl = facebookurl
		self.flat = flat

class College(Base):
	__tablename__ = "colleges"
	id = Column(Integer, primary_key=True)
	collegename = Column(String)
	users = relationship("User")
	buildings = relationship("Building")

	def __init__(self, collegename):
		self.collegename = collegename

class Building(Base):
	__tablename__ = "buildings"
	id = Column(Integer, primary_key=True)
	buildingcode = Column(String)
	buildingname = Column(String)
	collegeid = Column(Integer, ForeignKey("colleges.id"))
	buildingtype = Column(String)
	numflats = Column(Integer)
	users = relationship("User")

	def __init__(self, buildingcode, buildingname, collegeid, buildingtype, numflats):
		self.buildingcode = buildingcode
		self.buildingname = buildingname
		self.collegeid = collegeid
		self.buildingtype = buildingtype
		self.numflats = numflats

class ValidationLink(Base):
	__tablename__ = "validationlinks"
	id = Column(Integer, primary_key=True)
	key = Column(String)
	username = Column(String)
	pwhash = Column(String)

	def __init__(self, key, username, pwhash):
		self.key = key
		self.username = username
		self.pwhash = pwhash
