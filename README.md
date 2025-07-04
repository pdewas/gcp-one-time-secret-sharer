PROJECT_ID="secrets-sharing-externally"
REGION="europe-west4"
SERVICE_ACCOUNT_EMAIL="sa-share@secrets-sharing-externally.iam.gserviceaccount.com"
gcloud builds submit --tag "gcr.io/secrets-sharing-externally/secret-sharer" .

gcloud run deploy secret-sharer \
  --image "gcr.io/$PROJECT_ID/secret-sharer" \
  --platform managed \
  --region "$REGION" \
  --service-account "$SERVICE_ACCOUNT_EMAIL" \
  --no-allow-unauthenticated \
  --ingress=all \
  --update-secrets=oauth-client-id=oauth-client-id:latest,oauth-client-secret=oauth-client-secret:latest