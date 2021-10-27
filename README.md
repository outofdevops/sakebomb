# SAKeBomb
SAKe(y)Bomb Create Short Lived Service Account Keys

This utility has two commands:
* Generate
* Create

## Usage
Use it to mitigate risks of long-lived Service Account Keys 
![](images/help.png)

## Generate
It generates the key pair in PEM format, the public key can be uploaded directly via 
![](images/generate.png)

## Create
It generates keys locally and pushes the public key to GCP. The private they can be used to sign JWTs or embedded in a JSON file (see [How to create json SA key from pem file](#how-to-create-json-sa-key-from-pem-file))

### Requirements
This command needs to have access to GCP to upload the public key (`roles/iam.serviceAccountKeyAdmin`)
![](images/create.png)

## How to create json SA key from pem file
Create 
```bash
jq -n \
  --arg PRIVATE_KEY "$(cat private.pem)" \
  --arg PROJECT_ID "<YOUR-GCP-PROJECT_ID>" \
  --arg CLIENT_EMAIL "<THE-SERVICE-ACCOUNT-EMAIL>" \
  --arg CLIENT_ID "<THE-SERVICE-ACCOUNT-UNIQUE-ID>" \
  --arg PRIVATE_KEY_ID "<THE-SERVICE-ACCOUNT-KEY-ID>" \
  '{
      "type": "service_account",
      "project_id": $PROJECT_ID,
      "private_key_id": $PRIVATE_KEY_ID,
      "private_key": $PRIVATE_KEY,
      "client_email": $CLIENT_EMAIL,
      "client_id": $CLIENT_ID,
      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
      "token_uri": "https://oauth2.googleapis.com/token",
      "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
      "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/\($CLIENT_EMAIL)"
  }' > private-key.json

```
