# ssl-expiry-checker-azure-func

An Azure Function to check SSL certificate expiry dates and send notifications via email.

## Prerequisites
- MySQL database to store SSL certificate data.
- [Azurite](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite?tabs=visual-studio%2Cblob-storage) for local Azure storage emulation.
- Azure Function App to host the function.
- [wrlc-fastapi-webhook](https://github.com/WRLC/wrlc-fastapi-webhook) to send email notifications.

## Local Development

1. **Clone the Repository**
   ```bash
   git clone git@github.com:WRLC/ssl-expiry-checker-azure-func.git
   cd ssl-expiry-checker-azure-func
   ```
   
2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Create the Database**
   ```sql
   CREATE DATABASE ssl_expiry_checker;
   USE ssl_expiry_checker;
   
   CREATE TABLE vm (
        Vmid int NOT NULL AUTO_INCREMENT,
        Name varchar(255) NOT NULL,
        PRIMARY KEY (Vmid)
   );

   CREATE TABLE certificate (
        Certid int NOT NULL AUTO_INCREMENT,
        Name varchar(255) NOT NULL,
        Public tinyint(1) NOT NULL,
        Vmid int DEFAULT NULL,
        PRIMARY KEY (Certid),
        FOREIGN KEY (Vmid) REFERENCES vm(Vmid)
   );
   
   CREATE TABLE domain (
        Domainid int NOT NULL AUTO_INCREMENT,
        Domain varchar(255) NOT NULL,
        Certid int DEFAULT NULL,
        PRIMARY KEY (Domainid),
        FOREIGN KEY (Certid) REFERENCES certificate(Certid)
   );
   ```

4. **Configure Environment Variables**

    Copy the `.env.template` file to `.env` and update the values accordingly:

    ```bash
    cp .env.template .env
    ```
   
    ```
    # Webhook credentials
    WEBHOOK_USER=
    WEBHOOK_PASS=
    WEBHOOK_URL=

    # Email configuration
    EMAIL_TO=
    EMAIL_SENDER=
    EMAIL_SUBJECT=

    # Datebase for storing certificate data
    DB_HOST=
    DB_USER=
    DB_PASS=
    DB_NAME=

    # Threshold for sending email (in days)
    EXPIRY_THRESHOLD=19

    # Frequency of the cron job (in NCRONTAB format)
    CRON_FREQUENCY="0 0 12 * * *"
    ```
   
5. **Run the Function Locally**
   ```bash
   func start
   ```
   
To test locally, before starting the function, set `run_on_startup=True` in `function_app.py`'s 
`@app_timer_trigger` decorator.

This ensures the function runs immediately when the function app starts regardless of the cron schedule.

Be sure to set it back to `False` before deploying to Azure.
