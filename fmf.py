import tornado.ioloop
import tornado.web
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
        if self.get_argument("key"):
            cursor.execute("SELECT username, hash, verificationid FROM verifications WHERE key=%s", (self.get_argument("key"),))
            verification = cursor.fetchone()
            if verification:
                cursor.execute("INSERT INTO users (username, hash) VALUES (%s, %s)", (verification[0], verification[1]))
                self.set_secure_cookie("FMF_auth", verification[1])
                self.redirect('/', permanent=False)
                return
        self.write("That doesn't seem to be a valid verification key. Sorry :/")

class LoginHandler(BaseHandler):
    def check_credentials(self, username, password):
        cursor.execute("SELECT hash FROM users WHERE username=%s", (username,))
        hash = cursor.fetchone()[0]
        return bcrypt.hashpw(password, hash) == hash
    
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
                self.render('login.html', alert=True, alerttype='alert-danger', alertmsg="<strong>Nope.</strong> Incorrect login details")
        elif self.get_argument("action") == "signup":
            hashpw = bcrypt.hashpw(self.get_argument("password"), bcrypt.gensalt())
            key = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(42))
            cursor.execute("INSERT INTO users (key, username, hash) VALUES (%s, %s, %s)", tuple([key, self.get_argument("email"), hashpw]))
            msgtext = """
            Hi Flatmate!
            Here's that link to get you started. Copy and paste this into your browser: 
            findmyflatmates.co.uk/verify?key={0}
            """.format(key)
            message = sendgrid.Message("noreply@findmyflatmates.co.uk", "Welcome to FMF!", msgtext)
            self.render('login.html', alert=True, alerttype='alert-success', alertmsg='We sent you an email to verify your account.')

class LogoutHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.clear_cookie("FMF_auth")
        self.redirect('/', permanent=False)

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
    
    urlparse.uses_netloc.append("postgres")
    url = urlparse.urlparse(os.environ["DATABASE_URL"])
    conn = psycopg2.connect(
        database=url.path[1:],
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port
    )
    
    cursor = conn.cursor()
    s = sendgrid.Sendgrid(os.environ["SENDGRID_USER"], os.environ["SENDGRID_PASS"], secure=True)

    application = tornado.web.Application([
        (r"/login", LoginHandler),
        (r"/logout", LogoutHandler),
        (r"/", MainHandler),
        (r"/verify", VerifyHandler),
        (r"/static/(.*)", tornado.web.StaticFileHandler, dict(path = STATIC_PATH)),
    ], **settings)

    application.listen(os.environ["PORT"])
    tornado.ioloop.IOLoop.instance().start()