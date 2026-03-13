/// Structured error codes and JSON error formatting for agent-first UX.
///
/// Error code taxonomy (dot-separated):
/// - `input.missing_arg`, `input.invalid_value`
/// - `auth.expired`, `auth.scope_denied`, `auth.missing_key`
/// - `provider.timeout`, `provider.upstream_error`, `provider.not_found`
/// - `tool.not_found`, `tool.execution_failed`

/// Classify an error into a dot-separated error code by inspecting its message.
pub fn classify_error(err: &dyn std::error::Error) -> &'static str {
    let msg = err.to_string().to_lowercase();

    if msg.contains("unknown tool") || msg.contains("not found") && msg.contains("tool") {
        "tool.not_found"
    } else if msg.contains("scope") || msg.contains("access denied") {
        "auth.scope_denied"
    } else if msg.contains("expired") {
        "auth.expired"
    } else if msg.contains("key not found")
        || msg.contains("missing key")
        || msg.contains("no keys found")
    {
        "auth.missing_key"
    } else if msg.contains("timeout") {
        "provider.timeout"
    } else if msg.contains("upstream") || msg.contains("bad gateway") || msg.contains("mcp error") {
        "provider.upstream_error"
    } else if msg.contains("provider") && msg.contains("not found") {
        "provider.not_found"
    } else if msg.contains("missing") || msg.contains("required") {
        "input.missing_arg"
    } else if msg.contains("invalid") || msg.contains("parse") {
        "input.invalid_value"
    } else if msg.contains("rate limit") || msg.contains("rate.exceeded") {
        "rate.exceeded"
    } else {
        "tool.execution_failed"
    }
}

/// Map an error code to a process exit code.
pub fn exit_code_for_error(err: &dyn std::error::Error) -> i32 {
    let code = classify_error(err);
    match code.split('.').next().unwrap_or("") {
        "input" => 2,
        "auth" => 3,
        "provider" => 4,
        "rate" => 5,
        _ => 1,
    }
}

/// Format a structured JSON error string for --output json mode.
pub fn format_structured_error(err: &dyn std::error::Error, verbose: bool) -> String {
    let code = classify_error(err);
    let exit = exit_code_for_error(err);
    let message = err.to_string();

    let mut error_obj = serde_json::json!({
        "error": {
            "code": code,
            "message": message,
            "exit_code": exit,
        }
    });

    if verbose {
        let mut chain = Vec::new();
        let mut source = std::error::Error::source(err);
        while let Some(cause) = source {
            chain.push(cause.to_string());
            source = std::error::Error::source(cause);
        }
        if !chain.is_empty() {
            error_obj["error"]["chain"] = serde_json::json!(chain);
        }
    }

    serde_json::to_string(&error_obj).unwrap_or_else(|_| {
        format!(
            "{{\"error\":{{\"code\":\"{code}\",\"message\":\"{message}\",\"exit_code\":{exit}}}}}"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_unknown_tool() {
        let err: Box<dyn std::error::Error> = "Unknown tool: 'foo'".into();
        assert_eq!(classify_error(&*err), "tool.not_found");
    }

    #[test]
    fn test_classify_scope_denied() {
        let err: Box<dyn std::error::Error> = "Access denied: scope check failed".into();
        assert_eq!(classify_error(&*err), "auth.scope_denied");
    }

    #[test]
    fn test_classify_expired() {
        let err: Box<dyn std::error::Error> = "Token expired".into();
        assert_eq!(classify_error(&*err), "auth.expired");
    }

    #[test]
    fn test_classify_generic() {
        let err: Box<dyn std::error::Error> = "something went wrong".into();
        assert_eq!(classify_error(&*err), "tool.execution_failed");
    }

    #[test]
    fn test_exit_codes() {
        let input_err: Box<dyn std::error::Error> = "missing required argument".into();
        assert_eq!(exit_code_for_error(&*input_err), 2);

        let auth_err: Box<dyn std::error::Error> = "Token expired at 12345".into();
        assert_eq!(exit_code_for_error(&*auth_err), 3);

        let provider_err: Box<dyn std::error::Error> = "upstream API timeout".into();
        assert_eq!(exit_code_for_error(&*provider_err), 4);
    }

    #[test]
    fn test_format_structured_error() {
        let err: Box<dyn std::error::Error> = "Unknown tool: 'nonexistent'".into();
        let json_str = format_structured_error(&*err, false);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["error"]["code"], "tool.not_found");
        assert_eq!(parsed["error"]["exit_code"], 1);
        assert!(parsed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("nonexistent"));
    }
}
