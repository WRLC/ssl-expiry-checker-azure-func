"""
Azure Function App to check the expiry of SSL certificates for a list of URLs.
"""
from datetime import datetime, timezone
import logging
import os
import ssl
# noinspection PyPackageRequirements
import azure.functions as func
import cryptography.exceptions
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader, select_autoescape
import mysql.connector
from mysql.connector import errorcode
import requests  # type:ignore[import-untyped]
from requests.auth import HTTPBasicAuth  # type:ignore[import-untyped]


app = func.FunctionApp()
load_dotenv()

if not os.getenv('CRON_FREQUENCY'):  # If the cron frequency is not set
    raise ValueError('CRON_FREQUENCY not set')  # raise ValueError

frequency = os.getenv('CRON_FREQUENCY')  # type:ignore[arg-type]  # Get the frequency from environment variable


# pylint: disable=too-few-public-methods
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
        if not os.getenv('WEBHOOK_URL'):  # If the webhook URL is not set
            raise ValueError('WEBHOOK_URL not set')  # Exit if the webhook URL is not set

        if not os.getenv('WEBHOOK_USER') or not os.getenv('WEBHOOK_PASS'):  # If the webhook user or password is not set
            raise ValueError('WEBHOOK_USER or WEBHOOK_PASS not set')  # Exit if the webhook user or password is not set

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
                auth=basic,  # Basic auth for webhook
                timeout=30  # Timeout for the request
            )

        except requests.exceptions.RequestException as e:  # Handle exceptions
            logging.error('Error: %s', e)  # Log the error
            raise  # Exit if there is an error

        if response.status_code != 201:  # If the response status code is not 201
            logging.error('Error %s: %s', response.status_code, response.text)  # Log the error
            raise requests.exceptions.RequestException()  # Exit if there is an error


# noinspection PyUnusedLocal, PyTypeChecker, PyUnresolvedReferences
@app.timer_trigger(
    schedule=frequency, arg_name="mytimer", run_on_startup=False, use_monitor=False)  # type:ignore[arg-type]
def ssl_expiry_checker(mytimer: func.TimerRequest) -> None:  # pylint: disable=unused-argument
    """
    Check the expiry of SSL certificates for a list of URLs.
    :param mytimer:
    :return:
    """
    if not os.getenv('EXPIRY_THRESHOLD'):  # If the certificate expires in less than X days
        raise ValueError('EXPIRY_THRESHOLD not set')  # Exit if the expiry threshold is not set

    certs = get_certificates(get_urls())  # Get the certificates for the list of URLs

    expiring = []  # List to hold expiring certificates

    for cert in certs:  # Loop through the certificates
        if not os.getenv('EXPIRY_THRESHOLD'):
            raise ValueError('EXPIRY_THRESHOLD not set')  # Exit if the expiry threshold is not set

        data = check_expiry(cert.encode())  # Check the expiry of the certificate

        if not isinstance(data['expires'], datetime):  # If the certificate has no expiration date
            cert_name = data['cn'] if data['cn'] else 'Unknown'  # Get the certificate name
            raise ValueError(f'Certificate {cert_name} has no expiration date')  # Exit if no date

        delta = data['expires'] - datetime.now(timezone.utc)  # Get the expiration datetime delta
        days = delta.days if delta.days else 90  # Get the number of days until expiry

        if days < int(os.getenv('EXPIRY_THRESHOLD')):  # type:ignore[arg-type]  # If the cert expires < X days

            logging.info('Certificate %s expires %s in days', data["cn"], days)  # Log the certificate expiry
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
        except (requests.exceptions.RequestException, ValueError) as e:  # Handle exceptions
            logging.error('Error sending email: %s', e)  # Log the error if there is an error sending the email
            raise  # Exit if there is an error sending the email

        logging.info('Email sent to %s', email.to)  # Log if the email is sent
        return  # Exit if there are expiring certificates

    logging.info('No expiring certificates')  # Log if there are no expiring certificates


def get_urls() -> list:
    """
    Get the list of URLs from environment variable
    :return: list of URLs
    """
    if not os.getenv('DB_HOST'):  # If db host is not set
        raise ValueError('DB_HOST not set')  # raise ValueError

    if not os.getenv('DB_USER'):  # If the db user is not set
        raise ValueError('DB_USER not set')  # raise ValueError

    if not os.getenv('DB_PASS'):  # If db password is not set
        raise ValueError('DB_PASS not set')  # raise ValueError

    if not os.getenv('DB_NAME'):  # If db name is not set
        raise ValueError('DB_NAME not set')  # raise ValueError

    try:
        conn = mysql.connector.connect(  # Connect to the database
            host=os.getenv('DB_HOST'),  # type:ignore[arg-type]  # Database host
            user=os.getenv('DB_USER'),  # type:ignore[arg-type]  # Database user
            password=os.getenv('DB_PASS'),  # type:ignore[arg-type]  # Database password
            database=os.getenv('DB_NAME'),  # type:ignore[arg-type]  # Database name
        )
    except mysql.connector.Error as err:  # Handle exceptions
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:  # If the error is access denied
            logging.error('Something is wrong with your user name or password')  # Log the error
        elif err.errno == errorcode.ER_BAD_DB_ERROR:  # If the error is bad database
            logging.error('Database does not exist')  # Log the error
        else:  # If the error is something else
            logging.error('Error connecting to database: %s', err)  # Log the error
        raise
    except Exception as e:  # Handle any other type of exception
        logging.error('Error connecting to database: %s', e)  # Log the error
        raise  # Exit if there is an error connecting to the database

    cursor = conn.cursor()  # Create a cursor

    cursor.execute(  # Get one domain for each certificate
        "SELECT certificate.Name AS Certificate, MIN(domain.Domain) as Domain from domain "
        "JOIN certificate on certificate.Certid = domain.Certid "
        "WHERE domain.Domain NOT LIKE '*.%' AND certificate.Public = TRUE "
        "GROUP BY certificate.Name;"
    )

    rows = cursor.fetchall()  # Fetch the results

    cursor.close()  # Close the cursor
    conn.close()  # Close the connection

    urls = [row[1] for row in rows]  # type:ignore[index]  # Get the list of URLs

    return urls  # Return the list of URLs


def get_certificates(urls: list) -> list:
    """
    Get the certificates for the list of URLs.
    :param urls: list of URLs
    :return: list of certificates
    """
    certs = []  # List to hold the certificates

    for url in urls:  # Loop through the URLs

        try:  # Try to get the certificate
            logging.info('Getting certificate for %s', url)  # Log the URL
            cert = ssl.get_server_certificate((url, 443))  # Get the certificate

        except cryptography.exceptions.InternalError as e:  # Handle exceptions
            logging.error('Error getting certificate for %s: %s', url, e)  # Log the error
            continue  # Skip if there is an error

        if cert not in certs:  # If the certificate is not already in the list
            certs.append(cert)  # Add the certificate to the list

    return certs


# noinspection PyUnresolvedReferences
def check_expiry(cryptography_cert_pem: bytes) -> dict[str, str | datetime]:
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

    domains = ext.value.get_values_for_type(x509.DNSName)  # type: ignore # Get the subject alternative names

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
    if not os.getenv('EMAIL_SUBJECT'):
        raise ValueError('EMAIL_SUBJECT not set')  # Exit if the email subject is not set

    if not os.getenv('EMAIL_TO'):
        raise ValueError('EMAIL_TO not set')  # Exit if the email to is not set

    if not os.getenv('EMAIL_SENDER'):
        raise ValueError('EMAIL_SENDER not set')  # Exit if the email sender is not set

    body = render_template(  # Build the email body
        'email.html',  # template
        expiring=expiring,  # expiring domains
    )

    email = Email(  # Create the email object
        subject=os.getenv('EMAIL_SUBJECT'),  # type:ignore[arg-type]  # subject
        body=body,  # body
        to=os.getenv('EMAIL_TO'),  # type:ignore[arg-type]  # recipient(s)
        sender=os.getenv('EMAIL_SENDER'),  # type:ignore[arg-type]  # sender
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
