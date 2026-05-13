use crate::core::jwt;
use crate::core::manifest::{AuthType, ManifestRegistry};
use crate::core::scope::ScopeConfig;
use crate::{AuthCommands, Cli, OutputFormat};

/// Execute: ati auth <subcommand>
pub async fn execute(cli: &Cli, subcmd: &AuthCommands) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        AuthCommands::Status => show_status(cli),
    }
}

fn show_status(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let token = match std::env::var("ATI_SESSION_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            println!("No session token set (ATI_SESSION_TOKEN not configured)");
            println!("Running in unrestricted mode — all tools accessible.");
            print_oauth_providers_section(cli);
            return Ok(());
        }
    };

    // Decode JWT (inspect without requiring verification key)
    let claims =
        jwt::inspect(&token).map_err(|e| format!("Cannot decode ATI_SESSION_TOKEN: {e}"))?;

    // Check if we can fully validate
    let verified = match jwt::config_from_env() {
        Ok(Some(config)) => jwt::validate(&token, &config).is_ok(),
        _ => false,
    };

    let scopes = ScopeConfig::from_jwt(&claims);

    match cli.output {
        OutputFormat::Json => {
            let info = serde_json::json!({
                "sub": claims.sub,
                "iss": claims.iss,
                "aud": claims.aud,
                "scope": claims.scope,
                "scopes": claims.scopes(),
                "tool_scopes": scopes.tool_scope_count(),
                "skill_scopes": scopes.skill_scope_count(),
                "help_enabled": scopes.help_enabled(),
                "exp": claims.exp,
                "iat": claims.iat,
                "jti": claims.jti,
                "job_id": claims.job_id,
                "sandbox_id": claims.sandbox_id,
                "time_remaining_secs": scopes.time_remaining(),
                "expired": scopes.is_expired(),
                "signature_verified": verified,
            });
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        OutputFormat::Table | OutputFormat::Text => {
            println!("Agent:    {}", claims.sub);
            if let Some(ref iss) = claims.iss {
                println!("Issuer:   {iss}");
            }
            println!("Audience: {}", claims.aud);

            let tool_count = scopes.tool_scope_count();
            let skill_count = scopes.skill_scope_count();
            let help = if scopes.help_enabled() {
                "help enabled"
            } else {
                "help disabled"
            };
            if let Some(ref job_id) = claims.job_id {
                println!("Job ID:   {job_id}");
            }
            if let Some(ref sandbox_id) = claims.sandbox_id {
                println!("Sandbox:  {sandbox_id}");
            }
            println!("Scopes:   {tool_count} tools, {skill_count} skills, {help}");
            if !claims.scope.is_empty() {
                println!("  {}", claims.scope);
            }

            if let Some(remaining) = scopes.time_remaining() {
                if remaining == 0 {
                    println!("Expires:  EXPIRED");
                } else {
                    let hours = remaining / 3600;
                    let minutes = (remaining % 3600) / 60;
                    let ts = chrono::DateTime::from_timestamp(claims.exp as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                        .unwrap_or_else(|| "unknown".into());
                    println!("Expires:  {ts} ({hours}h {minutes}m remaining)");
                }
            } else {
                println!("Expires:  never");
            }

            let verified_str = if verified {
                "YES"
            } else {
                "NO (public key not available)"
            };
            println!("Verified: {verified_str}");

            print_oauth_providers_section(cli);

            if scopes.is_expired() {
                tracing::warn!("your session has expired â tool calls will be denied");
            }
        }
    }

    Ok(())
}

fn print_oauth_providers_section(cli: &Cli) {
    let ati_dir = super::common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");
    let registry = match ManifestRegistry::load(&manifests_dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    let oauth_providers: Vec<_> = registry
        .list_providers()
        .into_iter()
        .filter(|p| matches!(p.auth_type, AuthType::Oauth2Pkce))
        .collect();

    if oauth_providers.is_empty() {
        return;
    }

    match cli.output {
        OutputFormat::Json => {
            let entries: Vec<_> = oauth_providers
                .iter()
                .map(|p| {
                    let tokens = crate::core::oauth_store::load(&p.name).ok().flatten();
                    serde_json::json!({
                        "provider": p.name,
                        "authorized": tokens.is_some(),
                        "expires_at": tokens.as_ref().map(|t| t.access_token_expires_at),
                        "scopes": tokens.as_ref().map(|t| t.scopes.clone()),
                        "refreshable": tokens.as_ref().is_some_and(|t| t.refresh_token.is_some()),
                    })
                })
                .collect();
            println!("{}", serde_json::json!({"oauth_providers": entries}));
        }
        _ => {
            println!();
            println!("OAuth providers:");
            for p in oauth_providers {
                match crate::core::oauth_store::load(&p.name) {
                    Ok(Some(t)) => {
                        let mins = t.access_remaining().num_minutes();
                        let status = if t.access_remaining().num_seconds() <= 0 {
                            "expired".to_string()
                        } else {
                            format!("authorized, expires in {mins} min")
                        };
                        let refreshable = if t.refresh_token.is_some() {
                            "refreshable"
                        } else {
                            "no refresh token"
                        };
                        println!("  {}: {status}, {refreshable}", p.name);
                    }
                    Ok(None) => {
                        println!(
                            "  {}: not authorized — run `ati provider authorize {}`",
                            p.name, p.name
                        );
                    }
                    Err(e) => {
                        println!("  {}: error reading tokens ({e})", p.name);
                    }
                }
            }
        }
    }
}
