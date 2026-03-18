/// Integration tests for rate limiting.
use ati::core::rate::{self, RateConfig, RateLimit};
use std::collections::HashMap;

#[test]
fn test_parse_rate_spec_variants() {
    let specs = vec![
        ("10/hour", 10, 3600),
        ("5/minute", 5, 60),
        ("1/second", 1, 1),
        ("100/day", 100, 86400),
        ("3/h", 3, 3600),
        ("7/m", 7, 60),
        ("2/s", 2, 1),
        ("50/d", 50, 86400),
        ("10/hr", 10, 3600),
        ("10/min", 10, 60),
        ("10/sec", 10, 1),
    ];

    for (spec, expected_count, expected_window) in specs {
        let rl =
            rate::parse_rate_spec(spec).unwrap_or_else(|e| panic!("Failed to parse '{spec}': {e}"));
        assert_eq!(rl.count, expected_count, "count mismatch for {spec}");
        assert_eq!(
            rl.window_secs, expected_window,
            "window mismatch for {spec}"
        );
    }
}

#[test]
fn test_parse_rate_spec_invalid() {
    assert!(rate::parse_rate_spec("abc/hour").is_err());
    assert!(rate::parse_rate_spec("10").is_err());
    assert!(rate::parse_rate_spec("10/week").is_err());
    assert!(rate::parse_rate_spec("").is_err());
    assert!(rate::parse_rate_spec("10/hour/extra").is_err());
}

#[test]
fn test_parse_rate_config_from_map() {
    let mut map = HashMap::new();
    map.insert("tool:github:*".to_string(), "10/hour".to_string());
    map.insert("tool:*".to_string(), "100/hour".to_string());

    let config = rate::parse_rate_config(&map).unwrap();
    assert_eq!(config.limits.len(), 2);
    assert_eq!(config.limits["tool:github:*"].count, 10);
    assert_eq!(config.limits["tool:*"].count, 100);
}

/// Combined stateful test -- must not run in parallel with other tests that set ATI_DIR.
/// We test: within limit, exceeding limit, persistence, and wildcard matching all in one test.
#[test]
fn test_check_and_record_stateful() {
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("ATI_DIR", tmp.path().to_str().unwrap());

    // --- Test: within limit then exceeding ---
    {
        let mut limits = HashMap::new();
        limits.insert(
            "tool:*".to_string(),
            RateLimit {
                count: 2,
                window_secs: 3600,
            },
        );
        let config = RateConfig { limits };

        assert!(rate::check_and_record("test_tool", &config).is_ok());
        assert!(rate::check_and_record("test_tool", &config).is_ok());

        // 3rd call should fail
        let result = rate::check_and_record("test_tool", &config);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Rate limit exceeded"),
            "Expected 'Rate limit exceeded' in: {err_msg}"
        );
        assert!(
            err_msg.contains("tool:*"),
            "Expected 'tool:*' in: {err_msg}"
        );
    }

    // --- Test: persistence ---
    {
        let state_path = tmp.path().join("rate-state.json");
        assert!(state_path.exists(), "rate-state.json should exist");

        let content = std::fs::read_to_string(&state_path).unwrap();
        let state: serde_json::Value = serde_json::from_str(&content).unwrap();
        let calls = state["calls"]["tool:*"].as_array().unwrap();
        assert_eq!(
            calls.len(),
            2,
            "Should have recorded 2 calls (not the failed 3rd)"
        );
    }

    // --- Test: wildcard pattern matching with fresh state ---
    {
        // Reset state for wildcard test
        let state_path = tmp.path().join("rate-state.json");
        let _ = std::fs::remove_file(&state_path);

        let mut limits = HashMap::new();
        limits.insert(
            "tool:github:*".to_string(),
            RateLimit {
                count: 2,
                window_secs: 3600,
            },
        );
        let config = RateConfig { limits };

        // github tools should count against the limit
        assert!(rate::check_and_record("github:search", &config).is_ok());
        assert!(rate::check_and_record("github:create_issue", &config).is_ok());

        // Third github call should fail
        let result = rate::check_and_record("github:list_repos", &config);
        assert!(result.is_err(), "Third github call should be rate limited");

        // Non-github tool should not be affected (no matching pattern)
        assert!(
            rate::check_and_record("linear:list_issues", &config).is_ok(),
            "Non-matching tool should not be rate limited"
        );
    }
}

#[test]
fn test_error_classification() {
    let err: Box<dyn std::error::Error> = "Rate limit exceeded for something".into();
    assert_eq!(ati::core::error::classify_error(&*err), "rate.exceeded");
    assert_eq!(ati::core::error::exit_code_for_error(&*err), 5);
}
