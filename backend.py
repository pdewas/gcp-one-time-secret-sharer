# --- backend.py ---
from google.cloud import secretmanager, resourcemanager_v3, firestore
from googleapiclient.discovery import build
from cryptography.fernet import Fernet
# Note: google_auth_oauthlib.flow is not directly used by these classes,
# but UserGCPClient expects credentials that might originate from it.
# Keeping it here for clarity or future use if credential handling within UserGCPClient changes.
# from google_auth_oauthlib.flow import Flow # Credentials are now passed directly

# --- Class for Backend Operations (using Cloud Run Service Account) ---
class GCPServiceManager:
    """Handles backend services using the app's environment service account."""

    def __init__(self, project_id: str):
        try:
            # When no credentials are provided, clients automatically use
            # the environment's service account (Application Default Credentials).
            self.db = firestore.Client(project=project_id)
            sm_client = secretmanager.SecretManagerServiceClient()

            # Fetch the encryption key to create a cipher
            key_name = sm_client.secret_version_path(project_id, "secret-sharer-encryption-key", 'latest')
            response = sm_client.access_secret_version(request={"name": key_name})
            self.cipher = Fernet(response.payload.data)
        except Exception as e:
            raise RuntimeError(f"Failed to initialize backend services. Ensure the service account has 'Firestore User' and 'Secret Manager Secret Accessor' roles. Details: {e}")

    def encrypt_secret(self, secret_value: str) -> bytes:
        return self.cipher.encrypt(secret_value.encode('utf-8'))

    def decrypt_secret(self, encrypted_value: bytes) -> str:
        return self.cipher.decrypt(encrypted_value).decode('utf-8')

# --- Class for User-Specific GCP Actions (using User's OAuth Credentials) ---
class UserGCPClient:
    """Handles GCP actions on behalf of the logged-in user."""

    def __init__(self, credentials): # credentials will be google.oauth2.credentials.Credentials
        self.credentials = credentials
        self.user_email = self._fetch_user_email()

    def _fetch_user_email(self):
        try:
            user_info_service = build('oauth2', 'v2', credentials=self.credentials)
            return user_info_service.userinfo().get().execute().get('email')
        except Exception:
            return None # Or handle more gracefully

    def list_projects(self) -> list:
        # Ensure credentials are valid and have the necessary permissions.
        client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
        return sorted([p.project_id for p in client.search_projects(request={})])

    def list_secrets(self, project_id: str) -> list:
        client = secretmanager.SecretManagerServiceClient(credentials=self.credentials)
        # The parent path is typically "projects/{project_id}"
        return list(client.list_secrets(parent=f"projects/{project_id}"))

    def get_secret_value(self, secret_version_name: str) -> str:
        # secret_version_name should be like "projects/{project_id}/secrets/{secret_id}/versions/{version_id_or_latest}"
        client = secretmanager.SecretManagerServiceClient(credentials=self.credentials)
        response = client.access_secret_version(name=secret_version_name)
        return response.payload.data.decode("UTF-8")
