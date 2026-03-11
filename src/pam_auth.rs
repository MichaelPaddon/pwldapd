/// PAM-based authentication for LDAP simple binds.

const PAM_SERVICE: &str = "pwldapd";

/// Warn at startup if the PAM service file is missing.
/// Without it PAM falls back to /etc/pam.d/other, which typically denies
/// all access, causing every bind to silently fail.
pub fn check_pam_service() {
    let path = format!("/etc/pam.d/{PAM_SERVICE}");
    if !std::path::Path::new(&path).exists() {
        tracing::warn!(
            "{path} not found — bind authentication will fail. \
             Create {path} before clients attempt to authenticate."
        );
    }
}

pub fn authenticate(username: &str, password: &str) -> bool {
    if password.is_empty() {
        return false;
    }
    match pam::Authenticator::with_password(PAM_SERVICE) {
        Ok(mut auth) => {
            auth.get_handler().set_credentials(username, password);
            match auth.authenticate() {
                Ok(()) => {
                    tracing::debug!("PAM authenticated '{username}'");
                    true
                }
                Err(e) => {
                    tracing::debug!("PAM rejected '{username}': {e}");
                    false
                }
            }
        }
        Err(e) => {
            tracing::error!("PAM init failed: {e}");
            false
        }
    }
}

