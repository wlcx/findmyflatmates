import sendgrid
import os

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