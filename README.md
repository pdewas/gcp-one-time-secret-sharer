# GCP Secret Sharer Application

This guide provides step-by-step instructions to deploy the Secret Sharer application on Google Cloud. The application runs on **Cloud Run**, uses **Firestore** for data storage, and leverages **Secret Manager** for credential management.

## Prerequisites

* A Google Cloud Project.
* The `gcloud` command-line tool installed and authenticated (`gcloud auth login`).
* The project code (`app.py`, `backend.py`, `requirements.txt`, `Dockerfile`) on your local machine.

---

## 1. Project & Environment Setup

These commands configure your local shell and enable the necessary Google Cloud services.

### Set Environment Variables

This simplifies the following commands by storing your configuration in variables.

```bash
export PROJECT_ID="secrets-sharing-externally"
export REGION="europe-west4"
export SERVICE_ACCOUNT_NAME="sa-share"
export SERVICE_ACCOUNT_EMAIL="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
```
### Enable GCP APIs
This command activates all the services required for the application to function.

```bash
gcloud services enable \
  iam.googleapis.com \
  run.googleapis.com \
  firestore.googleapis.com \
  secretmanager.googleapis.com \
  cloudbuild.googleapis.com
```
## 2. Service Account & IAM Configuration
We will create a dedicated service account for the Cloud Run instance to ensure it has only the permissions it needs.

### Create the Service Account
```bash
gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME \
  --display-name="Secret Sharer App Service Account" \
  --project=$PROJECT_ID
```
### Grant IAM Permissions
The service account needs permission to access Firestore and the secrets it requires.

```bash
# Allow the service account to use Firestore
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
  --role="roles/datastore.user"

# Allow the service account to access its required secrets
gcloud secrets add-iam-policy-binding secret-sharer-encryption-key \
  --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding oauth-client-id \
  --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding oauth-client-secret \
  --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
  --role="roles/secretmanager.secretAccessor"
```
## 3. Database & Secret Configuration
### Create Firestore Database
Create a Firestore database in Native mode for storing one-time secret links.

Navigate to the Firestore Console.

Click Select Native Mode.

Choose a location (e.g., a region within Europe) and click Create Database.

### Create Secrets in Secret Manager
The application requires three secrets to function.

```bash
# 1. The encryption key for securing data in Firestore
#    (Replace "YOUR_STRONG_ENCRYPTION_KEY" with a secure, random string)
gcloud secrets create secret-sharer-encryption-key --replication-policy="automatic"
echo "YOUR_STRONG_ENCRYPTION_KEY" | gcloud secrets versions add secret-sharer-encryption-key --data-file=-

# 2. Placeholders for OAuth credentials (values will be added in the next step)
gcloud secrets create oauth-client-id --replication-policy="automatic"
gcloud secrets create oauth-client-secret --replication-policy="automatic"
```
## 4. OAuth 2.0 Configuration
This is required to allow users to log in with their Google accounts.

### Configure the OAuth Consent Screen
Navigate to the OAuth consent screen.

Choose Internal user type and click Create.

Enter an App name (e.g., "GCP Secret Sharer"), a User support email, and a Developer contact email. Click Save and Continue.

On the Scopes page, click Add or Remove Scopes. Find and add the following scopes:

.../auth/userinfo.email

.../auth/cloud-platform

openid

Click Update, then Save and Continue, and finally Back to Dashboard.

### Create OAuth Client ID
Navigate to the Credentials page.

Click + Create Credentials and select OAuth client ID.

For Application type, select Web application.

Under Authorized redirect URIs, add the URL of your app: https://secret-sharer-696580064439.europe-west4.run.app.

Click Create. A pop-up will show your Client ID and Client Secret. Copy these values.

### Store OAuth Credentials in Secret Manager
Run the following commands, pasting your copied credentials when prompted.

```bash
# Paste your Client ID
echo "YOUR_CLIENT_ID.apps.googleusercontent.com" | gcloud secrets versions add oauth-client-id --data-file=-

# Paste your Client Secret
echo "YOUR_CLIENT_SECRET" | gcloud secrets versions add oauth-client-secret --data-file=-
```
## 5. Build & Deploy the Application
With all the configuration complete, you can now build and deploy the application.

### Build the Container Image
This command uses Cloud Build to create a container image from your code and Dockerfile.

```bash
gcloud builds submit --tag "gcr.io/$PROJECT_ID/secret-sharer" .
```
### Deploy to Cloud Run
This command deploys the container to Cloud Run, making it accessible on the web.

```bash
gcloud run deploy secret-sharer \
  --image "gcr.io/$PROJECT_ID/secret-sharer" \
  --platform managed \
  --region "$REGION" \
  --service-account "$SERVICE_ACCOUNT_EMAIL" \
  --allow-unauthenticated
```
Note: The --allow-unauthenticated flag makes the service publicly accessible, but users must still log in via Google OAuth to use the app's features.

## 6. Securing with IAP (Optional - Production)
For production environments, it is highly recommended to restrict access using Identity-Aware Proxy (IAP).

### Redeploy with Internal Ingress: First, make the service private.

```bash
gcloud run deploy secret-sharer --ingress=internal-and-cloud-load-balancing --region=$REGION
```
### Set up a Load Balancer: Create a Global External HTTPS Load Balancer and use your Cloud Run service as the backend. Follow the official guide.

### Enable IAP: On the load balancer's backend configuration, check the box to Enable Cloud IAP.

### Grant Access: Grant users the IAP-secured Web App User role in the IAM console so they can pass through the IAP authentication wall.
