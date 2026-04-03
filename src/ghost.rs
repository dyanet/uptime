use std::collections::HashSet;
use std::fs;
use std::path::Path;

use log::{error, info};
use serde::Serialize;

/// Ghost Admin API configuration.
pub struct GhostConfig {
    pub url: String,
    pub admin_key: String,
}

impl GhostConfig {
    /// Try to load from environment. Returns None if not configured.
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("GHOST_URL").ok()?;
        let key = std::env::var("GHOST_ADMIN_KEY").ok()?;
        if url.is_empty() || key.is_empty() {
            return None;
        }
        Some(Self {
            url: url.trim_end_matches('/').to_string(),
            admin_key: key,
        })
    }

    fn key_id(&self) -> &str {
        self.admin_key.split(':').next().unwrap_or("")
    }

    fn key_secret(&self) -> &str {
        self.admin_key.split(':').nth(1).unwrap_or("")
    }
}

#[derive(Serialize)]
struct GhostClaims {
    iat: usize,
    exp: usize,
    aud: String,
}

/// Create a Ghost Admin API JWT token.
fn create_ghost_jwt(config: &GhostConfig) -> Result<String, String> {
    let secret_hex = config.key_secret();
    let secret_bytes =
        hex::decode(secret_hex).map_err(|e| format!("invalid Ghost key hex: {e}"))?;

    let header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::HS256,
        kid: Some(config.key_id().to_string()),
        typ: Some("JWT".to_string()),
        ..Default::default()
    };

    let now = chrono::Utc::now().timestamp() as usize;
    let claims = GhostClaims {
        iat: now,
        exp: now + 300,
        aud: "/admin/".to_string(),
    };

    let key = jsonwebtoken::EncodingKey::from_secret(&secret_bytes);
    jsonwebtoken::encode(&header, &claims, &key).map_err(|e| format!("JWT encode failed: {e}"))
}

#[derive(Serialize)]
struct CreateMemberRequest {
    members: Vec<MemberData>,
}

#[derive(Serialize)]
struct MemberData {
    email: String,
    labels: Vec<LabelData>,
}

#[derive(Serialize)]
struct LabelData {
    name: String,
}

/// Load the set of already-synced emails from disk.
fn load_synced_emails(path: &Path) -> HashSet<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_lowercase())
        .collect()
}

/// Append a newly synced email to the tracking file.
fn mark_synced(path: &Path, email: &str) {
    use std::io::Write;
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{}", email.to_lowercase());
    }
}

/// Sync new recipient emails to Ghost CMS as subscribers tagged with 'uptime'.
/// Skips emails already synced (tracked in synced_file).
pub async fn sync_new_emails(config: &GhostConfig, emails: &[&str], synced_file: &Path) {
    let synced = load_synced_emails(synced_file);
    let new_emails: Vec<&&str> = emails
        .iter()
        .filter(|e| !synced.contains(&e.to_lowercase()))
        .collect();

    if new_emails.is_empty() {
        return;
    }

    let client = reqwest::Client::new();

    for email in new_emails {
        let token = match create_ghost_jwt(config) {
            Ok(t) => t,
            Err(e) => {
                error!("Ghost JWT creation failed: {e}");
                return;
            }
        };

        let url = format!("{}/ghost/api/admin/members/", config.url);
        let body = CreateMemberRequest {
            members: vec![MemberData {
                email: email.to_string(),
                labels: vec![LabelData {
                    name: "uptime".to_string(),
                }],
            }],
        };

        let resp = client
            .post(&url)
            .header("Authorization", format!("Ghost {token}"))
            .json(&body)
            .send()
            .await;

        match resp {
            Ok(resp) if resp.status().is_success() => {
                info!("Ghost: created subscriber {email}");
                mark_synced(synced_file, email);
            }
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                // 422 means duplicate — mark synced so we don't retry
                if status.as_u16() == 422 {
                    info!("Ghost: {email} already exists, marking synced");
                    mark_synced(synced_file, email);
                } else {
                    error!("Ghost: failed to create {email}: {status} — {text}");
                }
            }
            Err(e) => {
                error!("Ghost: request failed for {email}: {e}");
            }
        }
    }
}
