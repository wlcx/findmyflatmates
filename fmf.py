import os
import datetime
import tornado.ioloop
import tornado.web
from tornado.escape import json_encode
import psycopg2, urlparse
import bcrypt
import sendgrid
import random, string
import re
from rq import Queue
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from table_def import User, Building, College, VerificationLink
from worker import conn
from utils import send_verification_email
class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("FMF_auth")

class VerifyHandler(tornado.web.RequestHandler):
    def get(self):
        try:
            Session = sessionmaker(bind=engine)
            session = Session()
            verif_link = session.query(VerificationLink).filter(VerificationLink.key==self.get_argument("key")).first()
            if verif_link:
                #if link has expired
                if verif_link.created + datetime.timedelta(days=1) < datetime.datetime.now():
                    session.delete(verif_link)
                    session.commit()
                    self.render('login.html', alert=True, alerttype='alert-danger', alertmsg="That verification link has expired. Sign up again.")
                else:
                    validated_user = User(username=verif_link.username, pwhash=verif_link.pwhash)
                    session.add(validated_user)
                    session.delete(verif_link)
                    session.commit()
                    self.set_secure_cookie("FMF_auth", verif_link.username)
                    self.redirect('/', permanent=False)
                    return
            else:
                self.render('login.html', alert=True, alerttype='alert-danger', alertmsg="That didn't seem to be a valid verification key. Try signing up again.")
            session.close()
        except tornado.web.MissingArgumentError:        
            self.render('login.html', alert=True, alerttype='alert-danger', alertmsg="That didn't seem to be a valid verification key. Try signing up again.")

class LoginHandler(BaseHandler):
    def check_credentials(self, username, password):
        Session = sessionmaker(bind=engine)
        session = Session()
        res = session.query(User).filter(User.username==username).first()
        session.close()
        if (res.pwhash):
            return bcrypt.hashpw(password, res.pwhash) == res.pwhash
        else:
            return False
    
    def get(self):
        if self.current_user:
            self.redirect('/', permanent=False)
            return
        self.render('login.html', alert=False)

    def post(self):
        if self.get_argument("action") == 'login':
            if self.check_credentials(self.get_argument("email"), self.get_argument("password")):
                self.set_secure_cookie("FMF_auth", self.get_argument("email"))
                self.redirect('/', permanent=False)
            else:
                self.render('login.html', alert=True, alerttype='alert-danger', alertmsg="Incorrect login details")
        elif self.get_argument("action") == "signup":
            Session = sessionmaker(bind=engine)
            session = Session()
            pwhash = bcrypt.hashpw(self.get_argument("password"), bcrypt.gensalt())
            key = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(42))
            new_link = VerificationLink(key=key, username=self.get_argument("email"), pwhash=pwhash, created=datetime.datetime.now())
            session.add(new_link)
            session.commit()
            session.close()
            q.enqueue(send_verification_email, self.get_argument('email'), key)
            self.render('login.html', alert=True, alerttype='alert-success', alertmsg='We sent you an email to verify your account.')

class LogoutHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.clear_cookie("FMF_auth")
        self.redirect('/', permanent=False)

class AboutHandler(BaseHandler):
    @tornado.web.authenticated
    def post(self):
        Session = sessionmaker(engine)
        session = Session()
        u = session.query(User).filter(User.username==self.get_current_user()).first()
        c = session.query(College).filter(College.collegename==self.get_argument("college")).first()
        u.firstname = self.get_argument("firstname")
        u.lastname = self.get_argument("lastname")
        u.collegeid = c.id
        u.biography = self.get_argument("biography")
        u.facebookurl = self.get_argument("facebookurl")
        u.twitterurl = self.get_argument("twitterurl")
        u.subject = self.get_argument("subject")
        session.commit()
        session.close()

class AccommodationHandler(BaseHandler):
    @tornado.web.authenticated
    def post(self):
        if self.get_argument("roomcode"):
            match = re.match('^[A-Za-z]{1,3}\/[A-Za-z0-9]+\/[0-9]+$', self.get_argument('roomcode'))
            if match:
                Session = sessionmaker(engine)
                session = Session()
                u = session.query(User).filter(User.username==self.get_current_user()).first()
                roomcode = self.get_argument("roomcode").split('/')
                b = session.query(Building).filter(Building.buildingcode==roomcode[0] + '/' + roomcode[1]).first()
                if b:
                    u.roomnumber = int(roomcode[2])
                    u.buildingid = b.id
                    if b.buildingtype == 'flat' or b.buildingtype == 'house':
                        u.unitnumber = self.get_argument("unitnumber")
                    else:
                        u.unitnumber = None
                else:
                    self.write(json_encode({'status': False, 'response': 'Invalid room code'}))
                session.commit()
                session.close()
            else:
                self.write(json_encode({'status': False, 'response': 'Invalid room code'}))

class BuildingHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        if self.get_argument("roomcode"):
            match = re.match('^[A-Za-z]{1,3}\/[A-Za-z0-9]+\/[0-9]+$', self.get_argument('roomcode'))
            if match:
                s = self.get_argument("roomcode").upper().split('/')
                buildingcode = s[0] + '/' + s[1]
                Session = sessionmaker(engine)
                session = Session()
                b = session.query(Building).filter(Building.buildingcode==buildingcode).first()
                c = session.query(College).filter(College.id==b.collegeid).first()
                session.close()
                if b:
                    building = {
                        'buildingcode': b.buildingcode,
                        'buildingname': b.buildingname,
                        'collegeid': b.collegeid,
                        'collegename': c.collegename,
                        'buildingtype': b.buildingtype,
                        'numunits': b.numunits,
                    }
                    self.write(json_encode({'status': True, 'response': building}))
                else:
                    self.write(json_encode({'status': False, 'response': ''}))
            else:
                self.write(json_encode({'status': False, 'response': 'Not a valid room code'}))
        else:
            self.write(json_encode({'status': False, 'response': ''}))

class ValidBuildingHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        if self.get_argument("roomcode"):
            match = re.match('^[A-Za-z]{1,3}\/[A-Za-z0-9]+\/[0-9]+$', self.get_argument('roomcode'))
            if match:
                s = self.get_argument("roomcode").upper().split('/')
                buildingcode = s[0] + '/' + s[1]
                Session = sessionmaker(engine)
                session = Session()
                b = session.query(Building).filter(Building.buildingcode==buildingcode).first()
                if b:
                    c = session.query(College).filter(College.id==b.collegeid).first()
                session.close()
                if b:
                    building = {
                        'buildingcode': b.buildingcode,
                        'buildingname': b.buildingname,
                        'collegename': c.collegename,
                        'buildingtype': b.buildingtype,
                        'numunits': b.numunits,
                    }
                    self.write(json_encode(True))
                else:
                    self.write(json_encode("That room does not exist."))
            else:
                self.write(json_encode({'status': False, 'response': 'Not a valid room code'}))
        else:
            self.write(json_encode(False))

class MainHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        Session = sessionmaker(engine)
        session = Session()
        u = session.query(User).filter(User.username==self.get_current_user()).first()
        f = session.query(User).filter(User.buildingid==u.buildingid).filter(User.unitnumber==u.unitnumber).filter(User.id!=u.id).all()
        b = session.query(Building).filter(Building.id==u.buildingid).first()
        c = session.query(College).all()
        session.close()
        colleges = {}
        for college in c:
            colleges[college.id] = {
                'collegeid': college.id,
                'collegename': college.collegename,
            }
        user = {
            'username': u.username,
            'firstname': u.firstname,
            'lastname': u.lastname,
            'collegeid': u.collegeid,
            'roomcode': b.buildingcode + '/' + str(u.roomnumber) if b and u.roomnumber else None,
            'biography': u.biography,
            'facebookurl': u.facebookurl,
            'twitterurl': u.twitterurl,
            'subject': u.subject,
            'unitnumber': u.unitnumber,
            'signup': u.signup,
        }
        self.render('index.html', flatmates=f, user=user, colleges=colleges, building=b)

if __name__ == '__main__':
    settings = {
        "cookie_secret": os.environ["COOKIE_SECRET"],
        "debug": True,
        "login_url": "/login",
    }
    STATIC_PATH = os.path.join(os.path.dirname(__file__), 'static')
    
    engine = create_engine(os.environ["DATABASE_URL"])

    q = Queue('medium', connection=conn)

    application = tornado.web.Application([
        (r"/login", LoginHandler),
        (r"/logout", LogoutHandler),
        (r"/", MainHandler),
        (r"/verify", VerifyHandler),
        (r"/about", AboutHandler),
        (r"/buildings", BuildingHandler),
        (r"/checkbuilding", ValidBuildingHandler),
        (r"/accom", AccommodationHandler),
        (r"/static/(.*)", tornado.web.StaticFileHandler, dict(path = STATIC_PATH)),
    ], **settings)

    application.listen(os.environ["PORT"])
    tornado.ioloop.IOLoop.instance().start()