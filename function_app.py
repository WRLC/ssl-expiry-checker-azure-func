"""
Azure Function App to check the expiry of SSL certificates for a list of URLs.
"""
# noinspection PyPackageRequirements
import azure.functions as func
from datetime import datetime, timezone
import logging
import os
import ssl
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader, select_autoescape
import requests
from requests.auth import HTTPBasicAuth


app = func.FunctionApp()
load_dotenv()


class Email:
    """
    Email object
    """
    def __init__(self, subject: str, body: str, to: str, sender: str) -> None:
        """
        Email object

        :param subject: str
        :param body: str
        :param to: str
        :param sender: str
        :return: None
        """
        self.subject = subject
        self.body = body
        self.to = to
        self.sender = sender

    def send(self) -> None:
        """
        Send the email to webhook

        :return: None
        """
        basic = HTTPBasicAuth(os.getenv('WEBHOOK_USER'), os.getenv('WEBHOOK_PASS'))  # Basic auth for webhook

        try:  # Try to send the email
            response = requests.post(  # Send the email
                url=os.getenv('WEBHOOK_URL'),  # URL for the webhook
                json={  # JSON payload for the webhook
                    "subject": self.subject,  # subject of the email
                    "body": self.body,  # body of the email
                    "to": self.to,  # recipient(s)
                    "sender": self.sender  # sender
                },
                auth=basic  # Basic auth for webhook
            )

        except Exception as e:  # Handle exceptions
            logging.error(f'Error: {e}')  # Log the error
            raise  # Exit if there is an error

        if response.status_code != 201:  # If the response status code is not 201
            logging.error(f'Error {response.status_code}: {response.text}')  # Log the error


# noinspection PyUnusedLocal, PyTypeChecker, PyUnresolvedReferences
@app.timer_trigger(schedule=os.getenv('CRON_FREQUENCY'), arg_name="mytimer", run_on_startup=False, use_monitor=False)
def ssl_expiry_checker(mytimer: func.TimerRequest) -> None:
    """
    Check the expiry of SSL certificates for a list of URLs.
    :param mytimer:
    :return:
    """
    certs = get_certificates(get_urls())  # Get the certificates for the list of URLs

    expiring = []  # List to hold expiring certificates

    for cert in certs:  # Loop through the certificates

        data = check_expiry(cert.encode())  # Check the expiry of the certificate
        delta = data['expires'] - datetime.now(timezone.utc)  # Get the expiration datetime delta
        days = delta.days  # Get the number of days until expiry

        if days < int(os.getenv('EXPIRY_THRESHOLD')):  # If the certificate expires in less than X days

            logging.info(f'Certificate {data["cn"]} expires in {days} days')  # Log the certificate expiry
            expiring.append(  # Add the certificate to the list of expiring certificates
                {
                    'cert': data['cn'],
                    'delta': days,
                    'expires': data['expires'],
                    'domains': data['domains']
                }
            )

    if expiring:  # If there are expiring certificates

        email = construct_email(expiring)  # Construct the email

        try:  # Try to send the email
            email.send()  # Send the email
        except Exception as e:  # Handle exceptions
            logging.error(f'Error sending email: {e}')  # Log the error if there is an error sending the email
            raise  # Exit if there is an error sending the email

        logging.info(f'Email sent to {email.to}')  # Log if the email is sent
        return  # Exit if there are expiring certificates

    logging.info('No expiring certificates')  # Log if there are no expiring certificates


def get_urls() -> list:
    """
    Get the list of URLs from environment variable
    :return: list of URLs
    """
    return os.getenv('DOMAINS').split(',')  # Get the list of URLs from the environment variable


def get_certificates(urls: list) -> list:
    """
    Get the certificates for the list of URLs.
    :param urls: list of URLs
    :return: list of certificates
    """
    certs = []  # List to hold the certificates

    for url in urls:  # Loop through the URLs

        try:  # Try to get the certificate
            cert = ssl.get_server_certificate((url, 443))  # Get the certificate

        except Exception as e:  # Handle exceptions
            logging.error(f'Error getting certificate for {url}: {e}')  # Log the error
            continue  # Skip if there is an error

        if cert not in certs:  # If the certificate is not already in the list
            certs.append(cert)  # Add the certificate to the list

    return certs


# noinspection PyUnresolvedReferences
def check_expiry(cryptography_cert_pem: x509) -> dict[str, str]:
    """
    Check the expiry of the certificate.

    :param cryptography_cert_pem:
    :return:
    """
    cert = x509.load_pem_x509_certificate(cryptography_cert_pem)  # Load the certificate

    exp = cert.not_valid_after_utc  # Get the expiration date

    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value  # Get the common name

    ext = cert.extensions.get_extension_for_oid(  # Get the subject alternative name extension
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )

    domains = ext.value.get_values_for_type(x509.DNSName)  # Get the subject alternative names

    cert_dict = {  # Create the output dictionary
        'cn': cn,
        'domains': domains,
        'expires': exp,
    }

    return cert_dict


def construct_email(expiring) -> Email:
    """
    Construct the email object

    :param expiring:
    :return: Email object
    """

    body = render_template(  # Build the email body
        'email.html',  # template
        expiring=expiring,  # expiring domains
    )

    email = Email(  # Create the email object
        subject=os.getenv('EMAIL_SUBJECT'),  # subject
        body=body,  # body
        to=os.getenv('EMAIL_TO'),  # recipient(s)
        sender=os.getenv('EMAIL_SENDER'),  # sender
    )

    return email


def render_template(template, **kwargs) -> str:
    """
    Render a Jinja template with the variables passed in

    :param template: str
    :param kwargs: dict
    :return: str
    """
    env = Environment(  # create the environment
        loader=FileSystemLoader('templates'),  # load the templates from the templates directory
        autoescape=select_autoescape(['html', 'xml'])  # autoescape html and xml
    )

    template = env.get_template(template)  # get the template

    return template.render(**kwargs)  # render the template with the variables passed in
