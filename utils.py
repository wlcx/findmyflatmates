import sendgrid
import os
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from table_def import VerificationLink

def send_verification_email(username, key):
    s = sendgrid.Sendgrid(os.environ["SENDGRID_USER"], os.environ["SENDGRID_PASS"], secure=True)
    msgtext = """
            Hi Flatmate!
            Here's that link to get you started. Copy and paste this into your browser: 
            findmyflatmates.co.uk/verify?key={0}
            """.format(key)
    message = sendgrid.Message("noreply@findmyflatmates.co.uk", "Welcome to FMF!", msgtext)
    message.add_to(username + '@york.ac.uk')
    s.smtp.send(message)

def delete_expired_verification_links():
    engine = create_engine(os.environ["DATABASE_URL"])
    Session = sessionmaker(engine)
    session = Session()
    links = session.query(VerificationLink).all()
    for link in links:
        if link.created + datetime.timedelta(days=1) < datetime.datetime.now():
            session.delete(link)
    session.commit()
    session.close()

def send_new_flatmate_email(name, recipients):
    if recipients:
        s = sendgrid.Sendgrid(os.environ["SENDGRID_USER"], os.environ["SENDGRID_PASS"], secure=True)
        msgtext = """
                Hi Flatmate,
                {0} has joined your flat! Log in and get in touch!
                """.format(name)
        message = sendgrid.Message("noreply@findmyflatmates.co.uk", "We've found you a new Flatmate!", msgtext)
        for r in recipients:
            message.add_to(r + '@york.ac.uk')
        s.smtp.send(message)