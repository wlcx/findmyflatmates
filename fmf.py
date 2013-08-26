import tornado.ioloop
import tornado.web
import tornado.escape
import os
import psycopg2, urlparse
import bcrypt
import sendgrid
import random, string

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("FMF_auth")

class VerifyHandler(tornado.web.RequestHandler):
    def get(self):
        try:
            self.get_argument("key")
            v = get_verify(self.get_argument("key"))
            if v:
                cursor.execute("DELETE FROM verify WHERE key=%s", (self.get_argument("key"),))
                cursor.execute("INSERT INTO users (username, hash) VALUES (%s, %s)", (v["username"], v["hash"]))
                self.set_secure_cookie("FMF_auth", v["username"])
                self.redirect('/', permanent=False)
                return
        except tornado.web.MissingArgumentError:        
            self.render('login.html', alert=True, alerttype='alert-danger', alertmsg="That didn't seem to be a valid verification key. Try signing up again.")


class LoginHandler(BaseHandler):
    def check_credentials(self, username, password):
        hash = get_hash_by_username(username)
        if (hash):
            return bcrypt.hashpw(password, hash) == hash
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
            hashpw = bcrypt.hashpw(self.get_argument("password"), bcrypt.gensalt())
            key = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(42))
            cursor.execute("INSERT INTO verify (key, username, hash) VALUES (%s, %s, %s);", (key, self.get_argument("email"), hashpw))
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
        get_user_by_username()

    @tornado.web.authenticated
    def post(self):
        #this goes into the database IN ORDER. be careful
        user = (self.get_argument("firstname"), self.get_argument("lastname"), self.get_argument("collegeid"), self.get_argument("buildingname"), self.get_argument("room"), self.get_argument("biography"))

class FlatmatesHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        pass

class BuildingHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        if self.get_argument("buildingcode"):
            cursor.execute("SELECT buildingname, buildingtype, numflats FROM buildings WHERE buildingcode=%s", (self.get_argument("buildingcode"),))
            r = cursor.fetchone()
            if not r:
                self.write(tornado.escape.json_encode({}))
            else:
                self.write(tornado.escape.json_encode(dict(zip(('buildingname', 'buildingtype', 'numflats'), r))))
        else:
            self.write(tornado.escape.json_encode({}))

class MainHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render('index.html')

def get_verify(key):
    cursor.execute("SELECT username, hash FROM verify WHERE key=%s", (key,))
    try: 
        f = cursor.fetchone() 
    except ProgrammingError as e:
        print e
        return {}
    else:
        if f:
            return dict(zip(('username', 'hash'), f))
        else:
            return {}

def get_hash_by_username(username):
    cursor.execute("SELECT hash FROM users WHERE username=%s", (username,))
    try: 
        hash = cursor.fetchone()
    except ProgrammingError as e:
        print e
        return ''
    else:
        if hash:
            return hash[0]
        else:
            return ''

def get_user_by_username(username):
    cursor.execute("SELECT username, firstname, lastname, buildingid, room FROM users WHERE username=%s", (username,))
    try: 
        f = cursor.fetchone() 
    except ProgrammingError as e:
        print e
        return {}
    else:
        if f:
            return dict(zip(('username', 'firstname', 'lastname', 'buildingid', 'room'), f))
        else:
            return {}

if __name__ == '__main__':
    settings = {
        "cookie_secret": os.environ["COOKIE_SECRET"],
        "debug": True,
        "login_url": "/login",
    }
    STATIC_PATH = os.path.join(os.path.dirname(__file__), 'static')
    
    urlparse.uses_netloc.append("postgres")
    url = urlparse.urlparse(os.environ["DATABASE_URL"])
    conn = psycopg2.connect(
        database=url.path[1:],
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port
    )
    conn.autocommit = True
    
    cursor = conn.cursor()
    s = sendgrid.Sendgrid(os.environ["SENDGRID_USER"], os.environ["SENDGRID_PASS"], secure=True)

    application = tornado.web.Application([
        (r"/login", LoginHandler),
        (r"/logout", LogoutHandler),
        (r"/", MainHandler),
        (r"/verify", VerifyHandler),
        (r"/buildings", BuildingHandler),
        (r"/static/(.*)", tornado.web.StaticFileHandler, dict(path = STATIC_PATH)),
    ], **settings)

    application.listen(os.environ["PORT"])
    tornado.ioloop.IOLoop.instance().start()