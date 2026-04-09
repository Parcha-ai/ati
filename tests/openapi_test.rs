/// Integration tests for OpenAPI handler support.
///
/// Tests:
/// - Manifest loading with handler = "openapi"
/// - Tool registration from OpenAPI spec
/// - Parameter classification (path/query/header/body)
/// - Path parameter substitution
/// - Tag/operation filtering
/// - Auth detection
/// - ManifestRegistry integration (tools appear in list, search, etc.)
/// - Proxy server serves OpenAPI tools via /call, /mcp, /health
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helper: create a test OpenAPI spec + TOML manifest in a temp directory
// ---------------------------------------------------------------------------

const PETSTORE_SPEC: &str = r#"{
    "openapi": "3.0.3",
    "info": {
        "title": "Petstore",
        "version": "1.0.0",
        "description": "A sample pet store API"
    },
    "servers": [{ "url": "https://petstore.example.com/v3" }],
    "paths": {
        "/pet/{petId}": {
            "get": {
                "operationId": "getPetById",
                "summary": "Find pet by ID",
                "description": "Returns a single pet",
                "tags": ["pet"],
                "parameters": [
                    {
                        "name": "petId",
                        "in": "path",
                        "required": true,
                        "schema": { "type": "integer", "format": "int64" },
                        "description": "ID of pet to return"
                    }
                ],
                "responses": { "200": { "description": "successful operation" } }
            },
            "delete": {
                "operationId": "deletePet",
                "summary": "Deletes a pet",
                "tags": ["pet"],
                "parameters": [
                    {
                        "name": "petId",
                        "in": "path",
                        "required": true,
                        "schema": { "type": "integer" }
                    },
                    {
                        "name": "api_key",
                        "in": "header",
                        "schema": { "type": "string" }
                    }
                ],
                "responses": { "200": { "description": "successful operation" } }
            }
        },
        "/pet": {
            "post": {
                "operationId": "addPet",
                "summary": "Add a new pet to the store",
                "tags": ["pet"],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {
                                    "name": {
                                        "type": "string",
                                        "description": "Pet name"
                                    },
                                    "status": {
                                        "type": "string",
                                        "description": "Pet status in the store",
                                        "enum": ["available", "pending", "sold"]
                                    },
                                    "photoUrls": {
                                        "type": "array",
                                        "items": { "type": "string" }
                                    }
                                }
                            }
                        }
                    }
                },
                "responses": { "200": { "description": "OK" } }
            }
        },
        "/pet/findByStatus": {
            "get": {
                "operationId": "findPetsByStatus",
                "summary": "Finds Pets by status",
                "tags": ["pet"],
                "parameters": [
                    {
                        "name": "status",
                        "in": "query",
                        "description": "Status values to filter by",
                        "schema": { "type": "string", "enum": ["available", "pending", "sold"] }
                    }
                ],
                "responses": { "200": { "description": "OK" } }
            }
        },
        "/store/inventory": {
            "get": {
                "operationId": "getInventory",
                "summary": "Returns pet inventories by status",
                "tags": ["store"],
                "responses": { "200": { "description": "OK" } }
            }
        },
        "/user/{username}": {
            "get": {
                "operationId": "getUserByName",
                "summary": "Get user by user name",
                "tags": ["user"],
                "parameters": [
                    {
                        "name": "username",
                        "in": "path",
                        "required": true,
                        "schema": { "type": "string" }
                    }
                ],
                "responses": { "200": { "description": "OK" } }
            }
        }
    },
    "components": {
        "securitySchemes": {
            "api_key": {
                "type": "apiKey",
                "in": "header",
                "name": "api_key"
            },
            "petstore_auth": {
                "type": "oauth2",
                "flows": {
                    "clientCredentials": {
                        "tokenUrl": "https://petstore.example.com/oauth/token",
                        "scopes": {}
                    }
                }
            }
        }
    }
}"#;

/// Create a temp dir with specs/ and manifests/ subdirectories.
fn create_test_ati_dir(manifest_toml: &str, spec_json: &str, spec_filename: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    let specs_dir = dir.path().join("specs");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&specs_dir).unwrap();
    std::fs::create_dir_all(&manifests_dir).unwrap();

    // Write spec
    std::fs::write(specs_dir.join(spec_filename), spec_json).unwrap();

    // Write manifest
    std::fs::write(manifests_dir.join("petstore.toml"), manifest_toml).unwrap();

    dir
}

// ---------------------------------------------------------------------------
// Test: manifest loading with handler = "openapi" registers tools
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_manifest_loads_tools() {
    let manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
"#;

    let dir = create_test_ati_dir(manifest, PETSTORE_SPEC, "petstore.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();

    // Should have discovered all 6 operations
    let tools = registry.list_public_tools();
    assert!(tools.len() >= 6, "Expected >= 6 tools, got {}", tools.len());

    // Check specific tools exist with correct prefixed names
    assert!(registry.get_tool("petstore:getPetById").is_some());
    assert!(registry.get_tool("petstore:addPet").is_some());
    assert!(registry.get_tool("petstore:findPetsByStatus").is_some());
    assert!(registry.get_tool("petstore:getInventory").is_some());
    assert!(registry.get_tool("petstore:getUserByName").is_some());
    assert!(registry.get_tool("petstore:deletePet").is_some());
}

// ---------------------------------------------------------------------------
// Test: tag filtering (include_tags)
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_include_tags_filter() {
    let manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
openapi_include_tags = ["pet"]
"#;

    let dir = create_test_ati_dir(manifest, PETSTORE_SPEC, "petstore.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();

    let tools = registry.list_public_tools();
    // Only pet-tagged operations: getPetById, deletePet, addPet, findPetsByStatus
    assert_eq!(
        tools.len(),
        4,
        "Expected 4 pet-tagged tools, got {}",
        tools.len()
    );

    // Store and user tools should NOT be present
    assert!(registry.get_tool("petstore:getInventory").is_none());
    assert!(registry.get_tool("petstore:getUserByName").is_none());
}

// ---------------------------------------------------------------------------
// Test: exclude tags filter
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_exclude_tags_filter() {
    let manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
openapi_exclude_tags = ["store", "user"]
"#;

    let dir = create_test_ati_dir(manifest, PETSTORE_SPEC, "petstore.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();

    // Only pet-tagged operations remain
    assert!(registry.get_tool("petstore:getInventory").is_none());
    assert!(registry.get_tool("petstore:getUserByName").is_none());
    assert!(registry.get_tool("petstore:getPetById").is_some());
}

// ---------------------------------------------------------------------------
// Test: max_operations cap
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_max_operations() {
    let manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
openapi_max_operations = 2
"#;

    let dir = create_test_ati_dir(manifest, PETSTORE_SPEC, "petstore.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();

    let tools = registry.list_public_tools();
    assert_eq!(
        tools.len(),
        2,
        "Expected exactly 2 tools (capped), got {}",
        tools.len()
    );
}

// ---------------------------------------------------------------------------
// Test: exclude_operations filter
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_exclude_operations() {
    let manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
openapi_exclude_operations = ["deletePet", "getInventory"]
"#;

    let dir = create_test_ati_dir(manifest, PETSTORE_SPEC, "petstore.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();

    assert!(registry.get_tool("petstore:deletePet").is_none());
    assert!(registry.get_tool("petstore:getInventory").is_none());
    assert!(registry.get_tool("petstore:getPetById").is_some());
    assert!(registry.get_tool("petstore:addPet").is_some());
}

// ---------------------------------------------------------------------------
// Test: tool properties have correct structure
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_tool_properties() {
    let manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
"#;

    let dir = create_test_ati_dir(manifest, PETSTORE_SPEC, "petstore.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();

    // Check getPetById tool properties
    let (provider, tool) = registry.get_tool("petstore:getPetById").unwrap();
    assert_eq!(provider.name, "petstore");
    assert_eq!(provider.handler, "openapi");
    assert!(tool.description.contains("Find pet by ID"));
    assert_eq!(tool.endpoint, "/pet/{petId}");

    // Check input schema has petId param with path location
    let schema = tool.input_schema.as_ref().unwrap();
    let props = schema.get("properties").unwrap().as_object().unwrap();
    let pet_id_prop = props.get("petId").unwrap();
    assert_eq!(
        pet_id_prop
            .get("x-ati-param-location")
            .unwrap()
            .as_str()
            .unwrap(),
        "path"
    );
    assert_eq!(
        pet_id_prop.get("type").unwrap().as_str().unwrap(),
        "integer"
    );

    // Check required fields
    let required = schema.get("required").unwrap().as_array().unwrap();
    assert!(required.iter().any(|r| r.as_str() == Some("petId")));

    // Check tags come from the spec
    assert!(tool.tags.contains(&"pet".to_string()));
}

// ---------------------------------------------------------------------------
// Test: request body params get body location
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_body_params_location() {
    let manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
"#;

    let dir = create_test_ati_dir(manifest, PETSTORE_SPEC, "petstore.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();

    let (_, tool) = registry.get_tool("petstore:addPet").unwrap();
    let schema = tool.input_schema.as_ref().unwrap();
    let props = schema.get("properties").unwrap().as_object().unwrap();

    // Body params should have x-ati-param-location = "body"
    let name_prop = props.get("name").unwrap();
    assert_eq!(
        name_prop
            .get("x-ati-param-location")
            .unwrap()
            .as_str()
            .unwrap(),
        "body"
    );
}

// ---------------------------------------------------------------------------
// Test: query params get query location
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_query_params_location() {
    let manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
"#;

    let dir = create_test_ati_dir(manifest, PETSTORE_SPEC, "petstore.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();

    let (_, tool) = registry.get_tool("petstore:findPetsByStatus").unwrap();
    let schema = tool.input_schema.as_ref().unwrap();
    let props = schema.get("properties").unwrap().as_object().unwrap();

    let status_prop = props.get("status").unwrap();
    assert_eq!(
        status_prop
            .get("x-ati-param-location")
            .unwrap()
            .as_str()
            .unwrap(),
        "query"
    );
}

// ---------------------------------------------------------------------------
// Test: per-operation overrides
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_overrides() {
    let manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"

[provider.openapi_overrides.getPetById]
hint = "Use this to fetch a single pet by its numeric ID"
description = "Get a pet (overridden)"
tags = ["lookup", "single-entity"]
"#;

    let dir = create_test_ati_dir(manifest, PETSTORE_SPEC, "petstore.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();

    let (_, tool) = registry.get_tool("petstore:getPetById").unwrap();
    assert_eq!(tool.description, "Get a pet (overridden)");
    assert_eq!(
        tool.hint.as_deref(),
        Some("Use this to fetch a single pet by its numeric ID")
    );
    // Tags should be merged (spec tags + override tags)
    assert!(tool.tags.contains(&"pet".to_string()));
    assert!(tool.tags.contains(&"lookup".to_string()));
    assert!(tool.tags.contains(&"single-entity".to_string()));
}

// ---------------------------------------------------------------------------
// Test: graceful degradation when spec file is missing
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_missing_spec_graceful() {
    let manifest = r#"
[provider]
name = "broken"
description = "Broken API"
handler = "openapi"
base_url = "https://example.com"
openapi_spec = "nonexistent.json"
auth_type = "none"
"#;

    let dir = TempDir::new().unwrap();
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();
    std::fs::write(manifests_dir.join("broken.toml"), manifest).unwrap();

    // Should not panic — graceful degradation
    let registry = ati::core::manifest::ManifestRegistry::load(&manifests_dir).unwrap();
    // Provider loads but with 0 tools
    let tools = registry.list_public_tools();
    assert_eq!(tools.len(), 0);
}

// ---------------------------------------------------------------------------
// Test: OpenAPI tools coexist with HTTP tools
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_coexists_with_http_tools() {
    let dir = TempDir::new().unwrap();
    let specs_dir = dir.path().join("specs");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&specs_dir).unwrap();
    std::fs::create_dir_all(&manifests_dir).unwrap();

    // Write OpenAPI spec
    std::fs::write(specs_dir.join("petstore.json"), PETSTORE_SPEC).unwrap();

    // Write OpenAPI manifest
    let openapi_manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
"#;
    std::fs::write(manifests_dir.join("petstore.toml"), openapi_manifest).unwrap();

    // Write a traditional HTTP manifest
    let http_manifest = r#"
[provider]
name = "example_http"
description = "Example HTTP API"
base_url = "https://api.example.com"
auth_type = "bearer"
auth_key_name = "example_key"

[[tools]]
name = "search"
description = "Search for things"
endpoint = "/search"
method = "GET"

[tools.input_schema]
type = "object"

[tools.input_schema.properties.q]
type = "string"
description = "Search query"
"#;
    std::fs::write(manifests_dir.join("example.toml"), http_manifest).unwrap();

    let registry = ati::core::manifest::ManifestRegistry::load(&manifests_dir).unwrap();

    // Both providers should be present
    let providers = registry.list_providers();
    assert!(providers.len() >= 2);

    // Both tool types should be accessible
    assert!(registry.get_tool("petstore:getPetById").is_some());
    assert!(registry.get_tool("search").is_some());

    // Total tools: 6 OpenAPI + 1 HTTP = 7
    let tools = registry.list_public_tools();
    assert!(tools.len() >= 7, "Expected >= 7 tools, got {}", tools.len());
}

// ---------------------------------------------------------------------------
// Test: auth detection from spec
// ---------------------------------------------------------------------------

#[test]
fn test_auth_detection_bearer() {
    let spec_json = r#"{
        "openapi": "3.0.3",
        "info": { "title": "Test", "version": "1.0.0" },
        "paths": {},
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer"
                }
            }
        }
    }"#;

    let spec = ati::core::openapi::parse_spec(spec_json).unwrap();
    let (auth_type, extra) = ati::core::openapi::detect_auth(&spec);
    assert_eq!(auth_type, "bearer");
    assert!(extra.is_empty());
}

#[test]
fn test_auth_detection_apikey_query() {
    let spec_json = r#"{
        "openapi": "3.0.3",
        "info": { "title": "Test", "version": "1.0.0" },
        "paths": {},
        "components": {
            "securitySchemes": {
                "apiKey": {
                    "type": "apiKey",
                    "in": "query",
                    "name": "appid"
                }
            }
        }
    }"#;

    let spec = ati::core::openapi::parse_spec(spec_json).unwrap();
    let (auth_type, extra) = ati::core::openapi::detect_auth(&spec);
    assert_eq!(auth_type, "query");
    assert_eq!(extra.get("auth_query_name").unwrap(), "appid");
}

#[test]
fn test_auth_detection_oauth2() {
    let spec = ati::core::openapi::parse_spec(PETSTORE_SPEC).unwrap();
    let (auth_type, extra) = ati::core::openapi::detect_auth(&spec);
    // The petstore spec has both apiKey and oauth2 — first match wins
    // apiKey comes first alphabetically
    assert!(
        auth_type == "header" || auth_type == "oauth2",
        "Expected header or oauth2, got: {auth_type}"
    );
    if auth_type == "oauth2" {
        assert!(extra.contains_key("oauth2_token_url"));
    }
}

// ---------------------------------------------------------------------------
// Test: path parameter substitution
// ---------------------------------------------------------------------------

#[test]
fn test_path_param_substitution() {
    use ati::core::openapi;

    let spec = openapi::parse_spec(PETSTORE_SPEC).unwrap();
    let filters = openapi::OpenApiFilters {
        include_tags: vec![],
        exclude_tags: vec![],
        include_operations: vec!["getPetById".to_string()],
        exclude_operations: vec![],
        max_operations: None,
    };
    let tools = openapi::extract_tools(&spec, &filters);
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].endpoint, "/pet/{petId}");

    // Verify the tool has path location metadata
    let schema = &tools[0].input_schema;
    let props = schema.get("properties").unwrap().as_object().unwrap();
    let pet_id = props.get("petId").unwrap();
    assert_eq!(
        pet_id
            .get("x-ati-param-location")
            .unwrap()
            .as_str()
            .unwrap(),
        "path"
    );
}

// ---------------------------------------------------------------------------
// Test: YAML spec parsing
// ---------------------------------------------------------------------------

#[test]
fn test_yaml_spec_parsing() {
    let yaml_spec = r#"
openapi: "3.0.3"
info:
  title: YAML Test API
  version: "1.0.0"
paths:
  /hello:
    get:
      operationId: sayHello
      summary: Say hello
      responses:
        "200":
          description: OK
"#;

    let spec = ati::core::openapi::parse_spec(yaml_spec).unwrap();
    assert_eq!(spec.info.title, "YAML Test API");

    let ops = ati::core::openapi::list_operations(&spec);
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].operation_id, "sayHello");
}

// ---------------------------------------------------------------------------
// Test: proxy server serves OpenAPI tools
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_proxy_serves_openapi_tools() {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let dir = TempDir::new().unwrap();
    let specs_dir = dir.path().join("specs");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&specs_dir).unwrap();
    std::fs::create_dir_all(&manifests_dir).unwrap();

    std::fs::write(specs_dir.join("petstore.json"), PETSTORE_SPEC).unwrap();
    std::fs::write(
        manifests_dir.join("petstore.toml"),
        r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
"#,
    )
    .unwrap();

    let registry = ati::core::manifest::ManifestRegistry::load(&manifests_dir).unwrap();
    let keyring = ati::core::keyring::Keyring::empty();

    let skill_registry =
        ati::core::skill::SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = std::sync::Arc::new(ati::proxy::server::ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None,
        jwks_json: None,
        auth_cache: ati::core::auth_generator::AuthCache::new(),
        secret_backend: None,
    });

    let app = ati::proxy::server::build_router(state);

    // Test /health shows OpenAPI tools
    let req = axum::http::Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let health: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(health["status"], "ok");
    assert!(
        health["tools"].as_u64().unwrap() >= 6,
        "Expected >= 6 tools in health, got {}",
        health["tools"]
    );

    // Test MCP tools/list includes OpenAPI tools
    let mcp_list = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });

    let req = axum::http::Request::builder()
        .uri("/mcp")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&mcp_list).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let mcp_response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let tools_list = mcp_response["result"]["tools"].as_array().unwrap();
    assert!(
        tools_list.len() >= 6,
        "Expected >= 6 tools in MCP tools/list, got {}",
        tools_list.len()
    );

    // Verify a specific tool appears with correct name
    let pet_tool = tools_list
        .iter()
        .find(|t| t["name"] == "petstore:getPetById");
    assert!(
        pet_tool.is_some(),
        "petstore:getPetById not in MCP tools/list"
    );
    let pet_tool = pet_tool.unwrap();
    assert!(pet_tool["description"]
        .as_str()
        .unwrap()
        .contains("Find pet by ID"));
}

// ---------------------------------------------------------------------------
// Test: OpenAPI tools show up in list_openapi_providers
// ---------------------------------------------------------------------------

#[test]
fn test_list_openapi_providers() {
    let manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
"#;

    let dir = create_test_ati_dir(manifest, PETSTORE_SPEC, "petstore.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();

    let openapi_providers = registry.list_openapi_providers();
    assert_eq!(openapi_providers.len(), 1);
    assert_eq!(openapi_providers[0].name, "petstore");
}

// ---------------------------------------------------------------------------
// Test: operation listing for inspect command
// ---------------------------------------------------------------------------

#[test]
fn test_list_operations() {
    let spec = ati::core::openapi::parse_spec(PETSTORE_SPEC).unwrap();
    let ops = ati::core::openapi::list_operations(&spec);

    assert_eq!(ops.len(), 6);

    // Verify we have the expected operations
    let op_ids: Vec<&str> = ops.iter().map(|o| o.operation_id.as_str()).collect();
    assert!(op_ids.contains(&"getPetById"));
    assert!(op_ids.contains(&"addPet"));
    assert!(op_ids.contains(&"findPetsByStatus"));
    assert!(op_ids.contains(&"getInventory"));
    assert!(op_ids.contains(&"getUserByName"));
    assert!(op_ids.contains(&"deletePet"));
}

// ---------------------------------------------------------------------------
// Test: collection format metadata injection — array with default style (multi)
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_collection_format_multi_default() {
    let spec_json = r#"{
        "openapi": "3.0.3",
        "info": { "title": "Test", "version": "1.0.0" },
        "paths": {
            "/pets": {
                "get": {
                    "operationId": "findPets",
                    "summary": "Find pets",
                    "parameters": [
                        {
                            "name": "status",
                            "in": "query",
                            "schema": {
                                "type": "array",
                                "items": { "type": "string" }
                            }
                        }
                    ],
                    "responses": { "200": { "description": "OK" } }
                }
            }
        }
    }"#;

    let manifest = r#"
[provider]
name = "test"
description = "Test API"
handler = "openapi"
base_url = "https://example.com"
openapi_spec = "test.json"
auth_type = "none"
"#;

    let dir = create_test_ati_dir(manifest, spec_json, "test.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();
    let (_, tool) = registry.get_tool("test:findPets").unwrap();
    let schema = tool.input_schema.as_ref().unwrap();
    let props = schema.get("properties").unwrap().as_object().unwrap();
    let status = props.get("status").unwrap();

    // Default style=form + explode=true → "multi"
    assert_eq!(
        status
            .get("x-ati-collection-format")
            .unwrap()
            .as_str()
            .unwrap(),
        "multi"
    );
}

// ---------------------------------------------------------------------------
// Test: collection format — explode:false → csv
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_collection_format_csv() {
    let spec_json = r#"{
        "openapi": "3.0.3",
        "info": { "title": "Test", "version": "1.0.0" },
        "paths": {
            "/pets": {
                "get": {
                    "operationId": "findPets",
                    "summary": "Find pets",
                    "parameters": [
                        {
                            "name": "ids",
                            "in": "query",
                            "explode": false,
                            "schema": {
                                "type": "array",
                                "items": { "type": "integer" }
                            }
                        }
                    ],
                    "responses": { "200": { "description": "OK" } }
                }
            }
        }
    }"#;

    let manifest = r#"
[provider]
name = "test"
description = "Test API"
handler = "openapi"
base_url = "https://example.com"
openapi_spec = "test.json"
auth_type = "none"
"#;

    let dir = create_test_ati_dir(manifest, spec_json, "test.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();
    let (_, tool) = registry.get_tool("test:findPets").unwrap();
    let schema = tool.input_schema.as_ref().unwrap();
    let props = schema.get("properties").unwrap().as_object().unwrap();
    let ids = props.get("ids").unwrap();

    assert_eq!(
        ids.get("x-ati-collection-format")
            .unwrap()
            .as_str()
            .unwrap(),
        "csv"
    );
}

// ---------------------------------------------------------------------------
// Test: collection format — spaceDelimited → ssv
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_collection_format_ssv() {
    let spec_json = r#"{
        "openapi": "3.0.3",
        "info": { "title": "Test", "version": "1.0.0" },
        "paths": {
            "/pets": {
                "get": {
                    "operationId": "findPets",
                    "summary": "Find pets",
                    "parameters": [
                        {
                            "name": "tags",
                            "in": "query",
                            "style": "spaceDelimited",
                            "schema": {
                                "type": "array",
                                "items": { "type": "string" }
                            }
                        }
                    ],
                    "responses": { "200": { "description": "OK" } }
                }
            }
        }
    }"#;

    let manifest = r#"
[provider]
name = "test"
description = "Test API"
handler = "openapi"
base_url = "https://example.com"
openapi_spec = "test.json"
auth_type = "none"
"#;

    let dir = create_test_ati_dir(manifest, spec_json, "test.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();
    let (_, tool) = registry.get_tool("test:findPets").unwrap();
    let schema = tool.input_schema.as_ref().unwrap();
    let props = schema.get("properties").unwrap().as_object().unwrap();
    let tags = props.get("tags").unwrap();

    assert_eq!(
        tags.get("x-ati-collection-format")
            .unwrap()
            .as_str()
            .unwrap(),
        "ssv"
    );
}

// ---------------------------------------------------------------------------
// Test: collection format — pipeDelimited → pipes
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_collection_format_pipes() {
    let spec_json = r#"{
        "openapi": "3.0.3",
        "info": { "title": "Test", "version": "1.0.0" },
        "paths": {
            "/pets": {
                "get": {
                    "operationId": "findPets",
                    "summary": "Find pets",
                    "parameters": [
                        {
                            "name": "colors",
                            "in": "query",
                            "style": "pipeDelimited",
                            "schema": {
                                "type": "array",
                                "items": { "type": "string" }
                            }
                        }
                    ],
                    "responses": { "200": { "description": "OK" } }
                }
            }
        }
    }"#;

    let manifest = r#"
[provider]
name = "test"
description = "Test API"
handler = "openapi"
base_url = "https://example.com"
openapi_spec = "test.json"
auth_type = "none"
"#;

    let dir = create_test_ati_dir(manifest, spec_json, "test.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();
    let (_, tool) = registry.get_tool("test:findPets").unwrap();
    let schema = tool.input_schema.as_ref().unwrap();
    let props = schema.get("properties").unwrap().as_object().unwrap();
    let colors = props.get("colors").unwrap();

    assert_eq!(
        colors
            .get("x-ati-collection-format")
            .unwrap()
            .as_str()
            .unwrap(),
        "pipes"
    );
}

// ---------------------------------------------------------------------------
// Test: no collection format for scalar query params
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_no_collection_format_for_scalar() {
    let manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
"#;

    let dir = create_test_ati_dir(manifest, PETSTORE_SPEC, "petstore.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();

    // findPetsByStatus has a scalar string query param "status" (not array)
    let (_, tool) = registry.get_tool("petstore:findPetsByStatus").unwrap();
    let schema = tool.input_schema.as_ref().unwrap();
    let props = schema.get("properties").unwrap().as_object().unwrap();
    let status = props.get("status").unwrap();

    // Scalar params should NOT have collection format
    assert!(
        status.get("x-ati-collection-format").is_none(),
        "Scalar query params should not have x-ati-collection-format"
    );
}

// ---------------------------------------------------------------------------
// Test: form-urlencoded body encoding metadata
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_form_urlencoded_body() {
    let spec_json = r#"{
        "openapi": "3.0.3",
        "info": { "title": "Test", "version": "1.0.0" },
        "paths": {
            "/token": {
                "post": {
                    "operationId": "getToken",
                    "summary": "Get OAuth token",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "required": ["grant_type"],
                                    "properties": {
                                        "grant_type": { "type": "string" },
                                        "client_id": { "type": "string" },
                                        "client_secret": { "type": "string" }
                                    }
                                }
                            }
                        }
                    },
                    "responses": { "200": { "description": "OK" } }
                }
            }
        }
    }"#;

    let manifest = r#"
[provider]
name = "test"
description = "Test API"
handler = "openapi"
base_url = "https://example.com"
openapi_spec = "test.json"
auth_type = "none"
"#;

    let dir = create_test_ati_dir(manifest, spec_json, "test.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();
    let (_, tool) = registry.get_tool("test:getToken").unwrap();
    let schema = tool.input_schema.as_ref().unwrap();

    assert_eq!(
        schema.get("x-ati-body-encoding").unwrap().as_str().unwrap(),
        "form"
    );
}

// ---------------------------------------------------------------------------
// Test: JSON body does NOT get encoding flag
// ---------------------------------------------------------------------------

#[test]
fn test_openapi_json_body_no_encoding_flag() {
    let manifest = r#"
[provider]
name = "petstore"
description = "Petstore API"
handler = "openapi"
base_url = "https://petstore.example.com/v3"
openapi_spec = "petstore.json"
auth_type = "none"
"#;

    let dir = create_test_ati_dir(manifest, PETSTORE_SPEC, "petstore.json");
    let registry =
        ati::core::manifest::ManifestRegistry::load(&dir.path().join("manifests")).unwrap();

    // addPet has a JSON body
    let (_, tool) = registry.get_tool("petstore:addPet").unwrap();
    let schema = tool.input_schema.as_ref().unwrap();

    assert!(
        schema.get("x-ati-body-encoding").is_none(),
        "JSON body should not have x-ati-body-encoding flag"
    );
}

// ---------------------------------------------------------------------------
// Test: base URL extraction from spec
// ---------------------------------------------------------------------------

#[test]
fn test_spec_base_url() {
    let spec = ati::core::openapi::parse_spec(PETSTORE_SPEC).unwrap();
    let base_url = ati::core::openapi::spec_base_url(&spec);
    assert_eq!(base_url.as_deref(), Some("https://petstore.example.com/v3"));
}
