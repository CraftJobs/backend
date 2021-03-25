from quart import g
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import *


def send_mail(to: str, title: str, content_txt: str):
    msg = Mail(Email('CraftJobs <noreply@craftjobs.net>'), To(to), title,
               Content("text/plain", content_txt))
    g.sg.client.mail.send.post(request_body=msg.get())
