import os
import datetime
import tornado.ioloop
import tornado.web
from tornado.escape import json_encode
import psycopg2, urlparse
import bcrypt
import sendgrid
import random, string
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from table_def import User, Building, College, VerificationLink

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("FMF_auth")

class VerifyHandler(tornado.web.RequestHandler):
    def get(self):
        try:
            Session = sessionmaker(bind=engine)
            session = Session()
            link = session.query(VerificationLink).filter(VerificationLink.key==self.get_argument("key")).first()
            if res:
                validated_user = User(username=link.username, pwhash=link.pwhash)
                session.add(validated_user)
                session.delete(link)
                session.commit()
                self.set_secure_cookie("FMF_auth", v["username"])
                self.redirect('/', permanent=False)
                return
            else:
                self.render('login.html', alert=True, alerttype='alert-danger', alertmsg="That didn't seem to be a valid verification key. Try signing up again.")
        except tornado.web.MissingArgumentError:        
            self.render('login.html', alert=True, alerttype='alert-danger', alertmsg="That didn't seem to be a valid verification key. Try signing up again.")


class LoginHandler(BaseHandler):
    def check_credentials(self, username, password):
        Session = sessionmaker(bind=engine)
        session = Session()
        res = session.query(User).filter(User.username==username).first()
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
            new_link = VerificationLink(key=key, username=self.get_argument("email"), pwhash=pwhash)
            session.add(new_link)
            session.commit()
            msgtext = """
            Hi Flatmate!
            Here's that link to get you started. Copy and paste this into your browser: 
            findmyflatmates.co.uk/verify?key={0}
            """.format(key)
            message = sendgrid.Message("noreply@findmyflatmates.co.uk", "Welcome to FMF!", msgtext)
            message.add_to(self.get_argument('email') + '@york.ac.uk')
            s.smtp.send(message)
            self.render('login.html', alert=True, alerttype='alert-success', alertmsg='We sent you an email to verify your account.')

class LogoutHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.clear_cookie("FMF_auth")
        self.redirect('/', permanent=False)

class UserHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        Session = sessionmaker(engine)
        session = Session()
        u = session.query(User).filter(User.username==self.get_current_user()).first()
        b = session.query(Building).filter(Building.id==u.buildingid).first()
        if u:
            user = {
            'firstname': u.firstname, 
            'lastname': u.lastname,
            'username': u.username,
            'roomcode': b.buildingcode + '/' + str(u.roomnumber) if u.buildingid else None,
            'biography': u.biography,
            'college': u.collegeid,
            'facebookurl': u.facebookurl,
            'flat': u.flat,
            }
            self.write(json_encode({'status': 0, 'response': user}))
        else:
            self.write(json_encode({'status': 1, 'response': ''}))

    @tornado.web.authenticated
    def post(self):
        Session = sessionmaker(engine)
        session = Session()
        u = session.query(User).filter(User.username==self.get_current_user()).first()
        b = session.query(Building).filter(Building.id==u.buildingid).first()
        if u:
            user = {
            'firstname': u.firstname, 
            'lastname': u.lastname,
            'username': u.username,
            'college': u.collegeid,
            'roomcode': b.buildingcode + '/' + str(u.roomnumber) if u.buildingid else None,
            'biography': u.biography,
            'facebookurl': u.facebookurl,
            'flat': u.flat,
            }
            self.write(json_encode({'status': 0, 'response': user}))
        else:
            self.write(json_encode({'status': 1, 'response': ''}))

    @tornado.web.authenticated
    def post(self):
        Session = sessionmaker(engine)
        session = Session()
        roomcode = self.get_argument("roomcode").split('/')
        u = session.query(User).filter(User.username==self.get_current_user()).first()
        b = session.query(Building).filter(Building.buildingcode==roomcode[0] + '/' + roomcode[1]).first()
        u.firstname = self.get_argument("firstname")
        u.lastname = self.get_argument("lastname")
        u.collegeid = self.get_argument("college")
        u.buildingid = b.id
        u.roomnumber = int(roomcode[2])
        u.biography = self.get_argument("biography")
        u.facebookurl = self.get_argument("facebookurl")
        u.flat = self.get_argument("flat")
        session.commit()

class FlatmatesHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        pass

class BuildingHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        if self.get_argument("roomcode"):
            s = self.get_argument("roomcode").upper().split('/')
            buildingcode = s[0] + '/' + s[1]
            Session = sessionmaker(engine)
            session = Session()
            b = session.query(Building).filter(Building.buildingcode==buildingcode).first()
            if b:
                building = {
                    'buildingcode': b.buildingcode,
                    'buildingname': b.buildingname,
                    'collegeid': b.collegeid,
                    'buildingtype': b.buildingtype,
                    'numflats': b.numflats,
                }
                self.write(json_encode({'status': 0, 'response': building}))
            else:
                self.write(json_encode({'status': 1, 'response': ''}))
        else:
            self.write(json_encode({'status': 1, 'response': ''}))

class MainHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render('index.html')

if __name__ == '__main__':
    settings = {
        "cookie_secret": os.environ["COOKIE_SECRET"],
        "debug": True,
        "login_url": "/login",
    }
    STATIC_PATH = os.path.join(os.path.dirname(__file__), 'static')
    
    engine = create_engine(os.environ["DATABASE_URL"])
    
    s = sendgrid.Sendgrid(os.environ["SENDGRID_USER"], os.environ["SENDGRID_PASS"], secure=True)

    application = tornado.web.Application([
        (r"/login", LoginHandler),
        (r"/logout", LogoutHandler),
        (r"/", MainHandler),
        (r"/verify", VerifyHandler),
        (r"/users", UserHandler),
        (r"/buildings", BuildingHandler),
        #(r"/flatmates", FlatmatesHandler),
        (r"/static/(.*)", tornado.web.StaticFileHandler, dict(path = STATIC_PATH)),
    ], **settings)

    application.listen(os.environ["PORT"])
    tornado.ioloop.IOLoop.instance().start()