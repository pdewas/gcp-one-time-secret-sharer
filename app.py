import streamlit as st
import uuid
# from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.cloud import secretmanager, resourcemanager_v3, firestore
from cryptography.fernet import Fernet
# from streamlit.web.server.server import Server

# Scopes define the permissions the end-user will grant to the application.
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/cloud-platform",
    "openid"
]

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

    def __init__(self, credentials):
        self.credentials = credentials
        self.user_email = self._fetch_user_email()

    def _fetch_user_email(self):
        try:
            user_info_service = build('oauth2', 'v2', credentials=self.credentials)
            return user_info_service.userinfo().get().execute().get('email')
        except Exception:
            return None

    def list_projects(self) -> list:
        client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
        return sorted([p.project_id for p in client.search_projects(request={})])

    def list_secrets(self, project_id: str) -> list:
        client = secretmanager.SecretManagerServiceClient(credentials=self.credentials)
        return list(client.list_secrets(parent=f"projects/{project_id}"))

    def get_secret_value(self, secret_version_name: str) -> str:
        client = secretmanager.SecretManagerServiceClient(credentials=self.credentials)
        response = client.access_secret_version(name=secret_version_name)
        return response.payload.data.decode("UTF-8")

# --- Main Application Class ---
class SecretSharerApp:
    """The main Streamlit application orchestrator."""

    def __init__(self):
        st.set_page_config(page_title="GCP Secret Sharer")
        self._initialize_session_state()
        self.services = self._get_service_manager()

        # --- FETCH SECRETS ONCE ON STARTUP ---
        project_id = "secrets-sharing-externally"
        sm_client = secretmanager.SecretManagerServiceClient()

        try:
            # Get Client ID
            id_path = sm_client.secret_version_path(project_id, "oauth-client-id", 'latest')
            id_response = sm_client.access_secret_version(request={"name": id_path})
            self.oauth_client_id = id_response.payload.data.decode("UTF-8").strip()

            # Get Client Secret
            secret_path = sm_client.secret_version_path(project_id, "oauth-client-secret", 'latest')
            secret_response = sm_client.access_secret_version(request={"name": secret_path})
            self.oauth_client_secret = secret_response.payload.data.decode("UTF-8").strip()
        except Exception as e:
            st.error(f"Failed to fetch OAuth credentials from Secret Manager. Ensure the Cloud Run service account has the 'Secret Manager Secret Accessor' role on 'oauth_client_id' and 'oauth_client_secret'. Details: {e}")
            st.stop()

    @staticmethod
    @st.cache_resource
    def _get_service_manager():
        project_id = "secrets-sharing-externally"
        return GCPServiceManager(project_id)

    def _initialize_session_state(self):
        if 'user_client' not in st.session_state:
            st.session_state.user_client = None
        if 'auth_flow' not in st.session_state:
            st.session_state.auth_flow = None

    def _get_base_url(self):
        return f"https://secret-sharer-696580064439.europe-west4.run.app"

    def run(self):
        """Main control flow for the app."""
        params = st.query_params

        if 'code' in params and not st.session_state.user_client:
            self._handle_oauth_callback(params['code'])
        elif 'token' in params:
            self._render_secret_display_view(params['token'])
        elif st.session_state.user_client:
            self._render_main_app_view()
        else:
            self._render_login_view()

    def _handle_oauth_callback(self, auth_code: str):
        """Exchanges the auth code for user credentials."""
        flow = st.session_state.auth_flow or self._create_auth_flow()
        flow.fetch_token(code=auth_code)
        st.session_state.user_client = UserGCPClient(flow.credentials)
        st.query_params.clear()
        st.rerun()

    def _render_login_view(self):
        """Shows the login button to start the OAuth flow."""
        st.header("Welcome to GCP Secret Sharer")
        st.write("Log in with Google to create one-time links for secrets you can access.")

        st.session_state.auth_flow = self._create_auth_flow()
        auth_url, _ = st.session_state.auth_flow.authorization_url(prompt='consent')
        st.link_button("Login with Google", auth_url)

    def _render_main_app_view(self):
        """The main UI for an authenticated user."""
        user_client = st.session_state.user_client
        st.header("Create a One-Time Secret Link")
        st.caption(f"Logged in as: {user_client.user_email}")

        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()

        try:
            projects = user_client.list_projects()
            if not projects:
                st.warning("No accessible GCP projects found.")
                return

            selected_project = st.selectbox("Select a Project", [""] + projects)

            if selected_project:
                secrets = user_client.list_secrets(selected_project)
                if not secrets:
                    st.info("No secrets found in this project.")
                    return

                for secret in secrets:
                    self._render_secret_widget(secret)
        except Exception as e:
            st.error(f"An error occurred: {e}")

    def _render_secret_widget(self, secret):
        """Renders the UI for a single secret."""
        user_client = st.session_state.user_client
        short_name = secret.name.split('/')[-1]
        link_state_key = f"link_for_{secret.name}"

        with st.expander(f"**{short_name}**"):
            if link_state_key in st.session_state:
                st.success("Link created! Share it now (it's only valid once).")
                st.code(st.session_state[link_state_key], language=None)
                if st.button("Done", key=f"done_{secret.name}"):
                    del st.session_state[link_state_key]
                    st.rerun()
            else:
                if st.button(f"Create one-time link", key=secret.name):
                    try:
                        secret_value = user_client.get_secret_value(f"{secret.name}/versions/latest")
                        encrypted_secret = self.services.encrypt_secret(secret_value)

                        token = str(uuid.uuid4())
                        doc_ref = self.services.db.collection('one_time_secrets').document(token)
                        doc_ref.set({'encrypted_secret': encrypted_secret})

                        st.session_state[link_state_key] = f"{self._get_base_url()}?token={token}"
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to create link: {e}")

    def _render_secret_display_view(self, token: str):
        """Displays the secret from a one-time link and deletes it."""
        st.header("One-Time Secret")
        doc_ref = self.services.db.collection('one_time_secrets').document(token)
        doc = doc_ref.get()

        if doc.exists:
            doc_ref.delete()
            decrypted_secret = self.services.decrypt_secret(doc.to_dict()['encrypted_secret'])
            st.success("Secret retrieved. This link is now invalid.")
            st.code(decrypted_secret, language=None)
        else:
            st.error("This link is invalid or has already been used.")

    def _create_auth_flow(self):
        """Creates the OAuth Flow object using credentials fetched during startup."""
        client_config = {
            "web": {
                "client_id": self.oauth_client_id,
                "client_secret": self.oauth_client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [self._get_base_url()],
            }
        }
        return Flow.from_client_config(client_config, scopes=SCOPES, redirect_uri=self._get_base_url())

if __name__ == "__main__":
    app = SecretSharerApp()
    app.run()