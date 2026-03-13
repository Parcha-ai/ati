/// OpenAPI spec parser — loads OpenAPI 3.x specs and generates ATI Tool definitions.
///
/// Supports both JSON and YAML specs (local files or URLs).
/// Each operation in the spec becomes an ATI tool with:
///   - Name: `{provider}__{operationId}` (or auto-generated from method + path)
///   - Description from operation summary/description
///   - Input schema with `x-ati-param-location` metadata for path/query/header/body routing
///   - HTTP method from the spec
///
/// Filters: include/exclude by tags and operationIds, max operations cap.
use openapiv3::{
    OpenAPI, Operation, Parameter, ParameterData, ParameterSchemaOrContent, QueryStyle,
    ReferenceOr, Schema, SchemaKind, Type as OAType,
};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::core::manifest::{
    HttpMethod, OpenApiToolOverride, Provider, ResponseConfig, ResponseFormat, Tool,
};

/// Errors specific to OpenAPI spec loading.
#[derive(Debug, thiserror::Error)]
pub enum OpenApiError {
    #[error("Failed to read spec file {0}: {1}")]
    Io(String, std::io::Error),
    #[error("Failed to parse spec as YAML: {0}")]
    YamlParse(String),
    #[error("Unsupported spec format: {0}")]
    UnsupportedFormat(String),
}

/// Filter configuration derived from Provider fields.
pub struct OpenApiFilters {
    pub include_tags: Vec<String>,
    pub exclude_tags: Vec<String>,
    pub include_operations: Vec<String>,
    pub exclude_operations: Vec<String>,
    pub max_operations: Option<usize>,
}

impl OpenApiFilters {
    pub fn from_provider(provider: &Provider) -> Self {
        OpenApiFilters {
            include_tags: provider.openapi_include_tags.clone(),
            exclude_tags: provider.openapi_exclude_tags.clone(),
            include_operations: provider.openapi_include_operations.clone(),
            exclude_operations: provider.openapi_exclude_operations.clone(),
            max_operations: provider.openapi_max_operations,
        }
    }
}

/// An extracted operation from an OpenAPI spec, before conversion to ATI Tool.
#[derive(Debug, Clone)]
pub struct OpenApiToolDef {
    pub operation_id: String,
    pub description: String,
    pub method: HttpMethod,
    pub endpoint: String,
    pub input_schema: Value,
    pub tags: Vec<String>,
}

/// Load an OpenAPI spec and produce ATI Tool definitions for a provider.
/// Called during ManifestRegistry::load() for handler = "openapi".
pub fn load_and_register(
    provider: &Provider,
    spec_ref: &str,
    specs_dir: Option<&Path>,
) -> Result<Vec<Tool>, OpenApiError> {
    let spec = load_spec(spec_ref, specs_dir)?;
    let filters = OpenApiFilters::from_provider(provider);
    let defs = extract_tools(&spec, &filters);
    let tools: Vec<Tool> = defs
        .into_iter()
        .map(|def| to_ati_tool(def, &provider.name, &provider.openapi_overrides))
        .collect();
    Ok(tools)
}

/// Load an OpenAPI spec from a file path or URL.
/// Supports JSON and YAML. If `spec_ref` is a relative path, resolves against `specs_dir`.
pub fn load_spec(spec_ref: &str, specs_dir: Option<&Path>) -> Result<OpenAPI, OpenApiError> {
    let content = if spec_ref.starts_with("http://") || spec_ref.starts_with("https://") {
        // URL — for now we don't support runtime fetching during load.
        // The `ati provider import-openapi` command downloads specs to ~/.ati/specs/.
        return Err(OpenApiError::UnsupportedFormat(
            "URL specs must be downloaded first with `ati provider import-openapi`. Use a local file path.".into(),
        ));
    } else {
        // Local file path
        let path = if Path::new(spec_ref).is_absolute() {
            std::path::PathBuf::from(spec_ref)
        } else if let Some(dir) = specs_dir {
            dir.join(spec_ref)
        } else {
            std::path::PathBuf::from(spec_ref)
        };
        std::fs::read_to_string(&path)
            .map_err(|e| OpenApiError::Io(path.display().to_string(), e))?
    };

    parse_spec(&content)
}

/// Parse an OpenAPI spec from a string (JSON or YAML).
pub fn parse_spec(content: &str) -> Result<OpenAPI, OpenApiError> {
    // Try JSON first, then YAML
    if let Ok(spec) = serde_json::from_str::<OpenAPI>(content) {
        return Ok(spec);
    }
    serde_yaml::from_str::<OpenAPI>(content).map_err(|e| OpenApiError::YamlParse(e.to_string()))
}

/// Extract tool definitions from an OpenAPI spec, applying filters.
pub fn extract_tools(spec: &OpenAPI, filters: &OpenApiFilters) -> Vec<OpenApiToolDef> {
    let mut tools = Vec::new();

    for (path_str, path_item_ref) in &spec.paths.paths {
        let path_item = match path_item_ref {
            ReferenceOr::Item(item) => item,
            ReferenceOr::Reference { .. } => continue, // Skip unresolved $ref paths
        };

        // Process each HTTP method on this path
        let methods: Vec<(&str, Option<&Operation>)> = vec![
            ("get", path_item.get.as_ref()),
            ("post", path_item.post.as_ref()),
            ("put", path_item.put.as_ref()),
            ("delete", path_item.delete.as_ref()),
            ("patch", path_item.patch.as_ref()),
        ];

        for (method_str, maybe_op) in methods {
            let operation = match maybe_op {
                Some(op) => op,
                None => continue,
            };

            // Derive operationId
            let operation_id = operation
                .operation_id
                .clone()
                .unwrap_or_else(|| auto_generate_operation_id(method_str, path_str));

            // Apply filters
            if !filters.include_operations.is_empty()
                && !filters.include_operations.contains(&operation_id)
            {
                continue;
            }
            if filters.exclude_operations.contains(&operation_id) {
                continue;
            }

            let op_tags: Vec<String> = operation.tags.clone();

            if !filters.include_tags.is_empty() {
                let has_included = op_tags.iter().any(|t| filters.include_tags.contains(t));
                if !has_included {
                    continue;
                }
            }
            if op_tags.iter().any(|t| filters.exclude_tags.contains(t)) {
                continue;
            }

            // Skip multipart/form-data (file uploads)
            if is_multipart(operation) {
                continue;
            }

            let method = match method_str {
                "get" => HttpMethod::Get,
                "post" => HttpMethod::Post,
                "put" => HttpMethod::Put,
                "delete" => HttpMethod::Delete,
                // PATCH maps to PUT as ATI doesn't have a Patch variant
                "patch" => HttpMethod::Put,
                _ => continue,
            };

            // Build description from summary + description
            let description = build_description(operation);

            // Build unified input schema with location metadata
            let input_schema = build_input_schema_with_locations(
                &path_item.parameters,
                &operation.parameters,
                &operation.request_body,
                spec,
            );

            tools.push(OpenApiToolDef {
                operation_id,
                description,
                method,
                endpoint: path_str.clone(),
                input_schema,
                tags: op_tags,
            });
        }
    }

    // Apply max_operations cap
    if let Some(max) = filters.max_operations {
        tools.truncate(max);
    }

    tools
}

/// Convert an extracted OpenAPI tool def into an ATI Tool struct.
pub fn to_ati_tool(
    def: OpenApiToolDef,
    provider_name: &str,
    overrides: &HashMap<String, OpenApiToolOverride>,
) -> Tool {
    let prefixed_name = format!("{}__{}", provider_name, def.operation_id);
    let override_cfg = overrides.get(&def.operation_id);

    let description = override_cfg
        .and_then(|o| o.description.clone())
        .unwrap_or(def.description);

    let hint = override_cfg.and_then(|o| o.hint.clone());

    let mut tags = def.tags;
    if let Some(extra) = override_cfg.map(|o| &o.tags) {
        tags.extend(extra.iter().cloned());
    }
    // Deduplicate tags
    tags.sort();
    tags.dedup();

    let examples = override_cfg.map(|o| o.examples.clone()).unwrap_or_default();

    let scope = override_cfg
        .and_then(|o| o.scope.clone())
        .unwrap_or_else(|| format!("tool:{prefixed_name}"));

    let response = override_cfg.and_then(|o| {
        if o.response_extract.is_some() || o.response_format.is_some() {
            Some(ResponseConfig {
                extract: o.response_extract.clone(),
                format: match o.response_format.as_deref() {
                    Some("markdown_table") => ResponseFormat::MarkdownTable,
                    Some("json") => ResponseFormat::Json,
                    Some("raw") => ResponseFormat::Raw,
                    _ => ResponseFormat::Text,
                },
            })
        } else {
            None
        }
    });

    Tool {
        name: prefixed_name,
        description,
        endpoint: def.endpoint,
        method: def.method,
        scope: Some(scope),
        input_schema: Some(def.input_schema),
        response,
        tags,
        hint,
        examples,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Auto-generate an operationId from method + path when the spec doesn't provide one.
/// E.g., ("get", "/pet/{petId}") → "get_pet_petId"
fn auto_generate_operation_id(method: &str, path: &str) -> String {
    let slug = path
        .trim_matches('/')
        .replace('/', "_")
        .replace('{', "")
        .replace('}', "");
    format!("{}_{}", method, slug)
}

/// Build a description string from operation summary and/or description.
fn build_description(op: &Operation) -> String {
    match (&op.summary, &op.description) {
        (Some(s), Some(d)) if s != d => format!("{s} — {d}"),
        (Some(s), _) => s.clone(),
        (_, Some(d)) => d.clone(),
        (None, None) => String::new(),
    }
}

/// Check if an operation uses multipart/form-data (file upload).
fn is_multipart(op: &Operation) -> bool {
    if let Some(ReferenceOr::Item(body)) = &op.request_body {
        return body.content.contains_key("multipart/form-data");
    }
    false
}

/// Extract ParameterData from a Parameter enum.
fn parameter_data(param: &Parameter) -> Option<&ParameterData> {
    match param {
        Parameter::Query { parameter_data, .. } => Some(parameter_data),
        Parameter::Header { parameter_data, .. } => Some(parameter_data),
        Parameter::Path { parameter_data, .. } => Some(parameter_data),
        Parameter::Cookie { parameter_data, .. } => Some(parameter_data),
    }
}

/// Get the location string for a Parameter.
fn parameter_location(param: &Parameter) -> &'static str {
    match param {
        Parameter::Query { .. } => "query",
        Parameter::Header { .. } => "header",
        Parameter::Path { .. } => "path",
        Parameter::Cookie { .. } => "query", // treat cookies as query for simplicity
    }
}

/// Resolve a $ref to a Parameter component.
fn resolve_parameter_ref<'a>(reference: &str, spec: &'a OpenAPI) -> Option<&'a ParameterData> {
    let name = reference.strip_prefix("#/components/parameters/")?;
    let param = spec.components.as_ref()?.parameters.get(name)?;
    match param {
        ReferenceOr::Item(p) => parameter_data(p),
        _ => None,
    }
}

/// Get location from a resolved parameter ref or direct parameter.
fn param_location_from_ref(param_ref: &ReferenceOr<Parameter>, spec: &OpenAPI) -> &'static str {
    match param_ref {
        ReferenceOr::Item(param) => parameter_location(param),
        ReferenceOr::Reference { reference } => {
            // Try to resolve and determine location
            let name = reference.strip_prefix("#/components/parameters/");
            if let Some(name) = name {
                if let Some(components) = &spec.components {
                    if let Some(ReferenceOr::Item(param)) = components.parameters.get(name) {
                        return parameter_location(param);
                    }
                }
            }
            "query" // default
        }
    }
}

/// Determine the collection format for an array query parameter.
/// Returns None for non-array or non-query params.
///
/// Mapping from OpenAPI 3.0 style/explode to ATI collection format:
/// - Form + explode:true (default) → "multi" (?status=a&status=b)
/// - Form + explode:false → "csv" (?status=a,b)
/// - SpaceDelimited → "ssv" (?status=a%20b)
/// - PipeDelimited → "pipes" (?status=a|b)
fn collection_format_for_param(param: &Parameter) -> Option<&'static str> {
    let (style, data) = match param {
        Parameter::Query {
            style,
            parameter_data,
            ..
        } => (style, parameter_data),
        _ => return None,
    };

    // Check if the parameter schema is an array type
    let is_array = match &data.format {
        ParameterSchemaOrContent::Schema(schema_ref) => match schema_ref {
            ReferenceOr::Item(schema) => {
                matches!(&schema.schema_kind, SchemaKind::Type(OAType::Array(_)))
            }
            ReferenceOr::Reference { .. } => false, // Can't resolve inline, skip
        },
        _ => false,
    };

    if !is_array {
        return None;
    }

    match style {
        QueryStyle::Form => {
            // Default explode for form is true
            let explode = data.explode.unwrap_or(true);
            if explode {
                Some("multi")
            } else {
                Some("csv")
            }
        }
        QueryStyle::SpaceDelimited => Some("ssv"),
        QueryStyle::PipeDelimited => Some("pipes"),
        QueryStyle::DeepObject => None, // Not a simple collection format
    }
}

/// Resolve a $ref to a full Parameter (preserving style info, unlike resolve_parameter_ref
/// which only returns ParameterData and loses style).
fn resolve_parameter_full_ref<'a>(reference: &str, spec: &'a OpenAPI) -> Option<&'a Parameter> {
    let name = reference.strip_prefix("#/components/parameters/")?;
    let param = spec.components.as_ref()?.parameters.get(name)?;
    match param {
        ReferenceOr::Item(p) => Some(p),
        _ => None,
    }
}

/// Build a unified input schema that preserves parameter locations.
/// This is the version called from extract_tools() with full context.
pub fn build_input_schema_with_locations(
    path_params: &[ReferenceOr<Parameter>],
    op_params: &[ReferenceOr<Parameter>],
    request_body: &Option<ReferenceOr<openapiv3::RequestBody>>,
    spec: &OpenAPI,
) -> Value {
    let mut properties = Map::new();
    let mut required_fields: Vec<String> = Vec::new();

    // Process all parameter refs with location info
    let all_param_refs: Vec<&ReferenceOr<Parameter>> =
        path_params.iter().chain(op_params.iter()).collect();

    for param_ref in &all_param_refs {
        let location = param_location_from_ref(param_ref, spec);
        let (data, collection_fmt) = match param_ref {
            ReferenceOr::Item(p) => (parameter_data(p), collection_format_for_param(p)),
            ReferenceOr::Reference { reference } => {
                let full = resolve_parameter_full_ref(reference, spec);
                (
                    full.and_then(parameter_data),
                    full.and_then(collection_format_for_param),
                )
            }
        };
        if let Some(data) = data {
            let mut prop = parameter_data_to_schema(data);
            // Inject location metadata
            if let Some(obj) = prop.as_object_mut() {
                obj.insert("x-ati-param-location".into(), json!(location));
                if let Some(cf) = collection_fmt {
                    obj.insert("x-ati-collection-format".into(), json!(cf));
                }
            }
            properties.insert(data.name.clone(), prop);
            if data.required {
                required_fields.push(data.name.clone());
            }
        }
    }

    // Add request body properties
    let mut body_encoding = "json";

    if let Some(body_ref) = request_body {
        let body = match body_ref {
            ReferenceOr::Item(b) => Some(b),
            ReferenceOr::Reference { reference } => resolve_request_body_ref(reference, spec),
        };

        if let Some(body) = body {
            // Detect content-type: prefer JSON, then form-urlencoded, then whatever's first
            let (media_type, detected_encoding) =
                if let Some(mt) = body.content.get("application/json") {
                    (Some(mt), "json")
                } else if let Some(mt) = body.content.get("application/x-www-form-urlencoded") {
                    (Some(mt), "form")
                } else {
                    (body.content.values().next(), "json")
                };
            body_encoding = detected_encoding;

            if let Some(mt) = media_type {
                if let Some(schema_ref) = &mt.schema {
                    let body_schema = resolve_schema_to_json(schema_ref, spec);
                    if let Some(body_props) =
                        body_schema.get("properties").and_then(|p| p.as_object())
                    {
                        let body_required: Vec<String> = body_schema
                            .get("required")
                            .and_then(|r| r.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();

                        for (k, v) in body_props {
                            let mut prop = v.clone();
                            if let Some(obj) = prop.as_object_mut() {
                                obj.insert("x-ati-param-location".into(), json!("body"));
                            }
                            properties.insert(k.clone(), prop);
                            if body.required && body_required.contains(k) {
                                required_fields.push(k.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    let mut schema = json!({
        "type": "object",
        "properties": Value::Object(properties),
    });

    if !required_fields.is_empty() {
        schema
            .as_object_mut()
            .unwrap()
            .insert("required".into(), json!(required_fields));
    }

    // Inject body encoding metadata for non-JSON content types
    if body_encoding == "form" {
        schema
            .as_object_mut()
            .unwrap()
            .insert("x-ati-body-encoding".into(), json!("form"));
    }

    schema
}

/// Convert a ParameterData into a JSON Schema property.
fn parameter_data_to_schema(data: &ParameterData) -> Value {
    let mut prop = Map::new();

    // Extract type from schema
    match &data.format {
        ParameterSchemaOrContent::Schema(schema_ref) => {
            let resolved = match schema_ref {
                ReferenceOr::Item(schema) => schema_to_json_type(schema),
                ReferenceOr::Reference { .. } => json!({"type": "string"}),
            };
            if let Some(obj) = resolved.as_object() {
                for (k, v) in obj {
                    prop.insert(k.clone(), v.clone());
                }
            }
        }
        ParameterSchemaOrContent::Content(_) => {
            prop.insert("type".into(), json!("string"));
        }
    }

    // Add description
    if let Some(desc) = &data.description {
        prop.insert("description".into(), json!(desc));
    }

    // Add example
    if let Some(example) = &data.example {
        prop.insert("example".into(), example.clone());
    }

    Value::Object(prop)
}

/// Convert an openapiv3 Schema to a simple JSON Schema type representation.
fn schema_to_json_type(schema: &Schema) -> Value {
    let mut result = Map::new();

    match &schema.schema_kind {
        SchemaKind::Type(t) => match t {
            OAType::String(s) => {
                result.insert("type".into(), json!("string"));
                if !s.enumeration.is_empty() {
                    let enums: Vec<Value> = s
                        .enumeration
                        .iter()
                        .filter_map(|e| e.as_ref().map(|v| json!(v)))
                        .collect();
                    result.insert("enum".into(), json!(enums));
                }
            }
            OAType::Number(_) => {
                result.insert("type".into(), json!("number"));
            }
            OAType::Integer(_) => {
                result.insert("type".into(), json!("integer"));
            }
            OAType::Boolean { .. } => {
                result.insert("type".into(), json!("boolean"));
            }
            OAType::Object(_) => {
                result.insert("type".into(), json!("object"));
            }
            OAType::Array(a) => {
                result.insert("type".into(), json!("array"));
                if let Some(items_ref) = &a.items {
                    match items_ref {
                        ReferenceOr::Item(items_schema) => {
                            let items_type = schema_to_json_type(items_schema);
                            result.insert("items".into(), items_type);
                        }
                        ReferenceOr::Reference { .. } => {
                            result.insert("items".into(), json!({"type": "object"}));
                        }
                    }
                }
            }
        },
        SchemaKind::OneOf { .. }
        | SchemaKind::AnyOf { .. }
        | SchemaKind::AllOf { .. }
        | SchemaKind::Not { .. }
        | SchemaKind::Any(_) => {
            // For complex schemas, default to string for CLI simplicity
            result.insert("type".into(), json!("string"));
        }
    }

    // Add description from schema_data
    if let Some(desc) = &schema.schema_data.description {
        result.insert("description".into(), json!(desc));
    }
    if let Some(def) = &schema.schema_data.default {
        result.insert("default".into(), def.clone());
    }
    if let Some(example) = &schema.schema_data.example {
        result.insert("example".into(), example.clone());
    }

    Value::Object(result)
}

/// Maximum recursion depth for schema resolution (prevents stack overflow from circular $ref).
const MAX_SCHEMA_DEPTH: usize = 32;

/// Resolve a Schema $ref to a JSON representation.
fn resolve_schema_to_json(schema_ref: &ReferenceOr<Schema>, spec: &OpenAPI) -> Value {
    resolve_schema_to_json_depth(schema_ref, spec, 0)
}

fn resolve_schema_to_json_depth(
    schema_ref: &ReferenceOr<Schema>,
    spec: &OpenAPI,
    depth: usize,
) -> Value {
    if depth >= MAX_SCHEMA_DEPTH {
        return json!({"type": "object", "description": "(schema too deeply nested)"});
    }

    match schema_ref {
        ReferenceOr::Item(schema) => {
            // Build a full JSON schema from the openapiv3 Schema
            let mut result = schema_to_json_type(schema);

            // If it's an object type, also extract properties
            if let SchemaKind::Type(OAType::Object(obj)) = &schema.schema_kind {
                let mut props = Map::new();
                for (name, prop_ref) in &obj.properties {
                    let prop_schema = match prop_ref {
                        ReferenceOr::Item(s) => schema_to_json_type(s.as_ref()),
                        ReferenceOr::Reference { reference } => {
                            resolve_schema_ref_to_json_depth(reference, spec, depth + 1)
                        }
                    };
                    props.insert(name.clone(), prop_schema);
                }
                if !props.is_empty() {
                    if let Some(obj) = result.as_object_mut() {
                        obj.insert("properties".into(), Value::Object(props));
                    }
                }
                if !obj.required.is_empty() {
                    if let Some(obj_map) = result.as_object_mut() {
                        obj_map.insert("required".into(), json!(obj.required));
                    }
                }
            }

            result
        }
        ReferenceOr::Reference { reference } => {
            resolve_schema_ref_to_json_depth(reference, spec, depth + 1)
        }
    }
}

/// Resolve a schema $ref string like "#/components/schemas/Pet" to JSON.
fn resolve_schema_ref_to_json(reference: &str, spec: &OpenAPI) -> Value {
    resolve_schema_ref_to_json_depth(reference, spec, 0)
}

fn resolve_schema_ref_to_json_depth(reference: &str, spec: &OpenAPI, depth: usize) -> Value {
    if depth >= MAX_SCHEMA_DEPTH {
        return json!({"type": "object", "description": "(schema too deeply nested)"});
    }

    let name = match reference.strip_prefix("#/components/schemas/") {
        Some(n) => n,
        None => return json!({"type": "object"}),
    };

    let schema = spec.components.as_ref().and_then(|c| c.schemas.get(name));

    match schema {
        Some(schema_ref) => resolve_schema_to_json_depth(schema_ref, spec, depth + 1),
        None => json!({"type": "object"}),
    }
}

/// Resolve a RequestBody $ref.
fn resolve_request_body_ref<'a>(
    reference: &str,
    spec: &'a OpenAPI,
) -> Option<&'a openapiv3::RequestBody> {
    let name = reference.strip_prefix("#/components/requestBodies/")?;
    let body = spec.components.as_ref()?.request_bodies.get(name)?;
    match body {
        ReferenceOr::Item(b) => Some(b),
        _ => None,
    }
}

/// Detect auth scheme from an OpenAPI spec's securitySchemes.
/// Returns (auth_type_str, extra_fields) for TOML manifest generation.
pub fn detect_auth(spec: &OpenAPI) -> (String, HashMap<String, String>) {
    let mut extra = HashMap::new();

    let schemes = match spec.components.as_ref() {
        Some(c) => &c.security_schemes,
        None => return ("none".into(), extra),
    };

    // Pick the first security scheme
    for (_name, scheme_ref) in schemes {
        let scheme = match scheme_ref {
            ReferenceOr::Item(s) => s,
            _ => continue,
        };

        match scheme {
            openapiv3::SecurityScheme::HTTP {
                scheme: http_scheme,
                ..
            } => {
                let scheme_lower = http_scheme.to_lowercase();
                if scheme_lower == "bearer" {
                    return ("bearer".into(), extra);
                } else if scheme_lower == "basic" {
                    return ("basic".into(), extra);
                }
            }
            openapiv3::SecurityScheme::APIKey { location, name, .. } => match location {
                openapiv3::APIKeyLocation::Header => {
                    extra.insert("auth_header_name".into(), name.clone());
                    return ("header".into(), extra);
                }
                openapiv3::APIKeyLocation::Query => {
                    extra.insert("auth_query_name".into(), name.clone());
                    return ("query".into(), extra);
                }
                openapiv3::APIKeyLocation::Cookie => {
                    return ("none".into(), extra);
                }
            },
            openapiv3::SecurityScheme::OAuth2 { flows, .. } => {
                // Check for client_credentials flow
                if let Some(cc) = &flows.client_credentials {
                    extra.insert("oauth2_token_url".into(), cc.token_url.clone());
                    return ("oauth2".into(), extra);
                }
            }
            openapiv3::SecurityScheme::OpenIDConnect { .. } => {
                // Not directly supported — leave for manual config
            }
        }
    }

    ("none".into(), extra)
}

/// Summarize operations in a spec for the `inspect` command.
pub struct OperationSummary {
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub description: String,
    pub tags: Vec<String>,
}

/// List all operations in an OpenAPI spec (unfiltered) for inspection.
pub fn list_operations(spec: &OpenAPI) -> Vec<OperationSummary> {
    let mut ops = Vec::new();

    for (path_str, path_item_ref) in &spec.paths.paths {
        let path_item = match path_item_ref {
            ReferenceOr::Item(item) => item,
            _ => continue,
        };

        let methods: Vec<(&str, Option<&Operation>)> = vec![
            ("GET", path_item.get.as_ref()),
            ("POST", path_item.post.as_ref()),
            ("PUT", path_item.put.as_ref()),
            ("DELETE", path_item.delete.as_ref()),
            ("PATCH", path_item.patch.as_ref()),
        ];

        for (method, maybe_op) in methods {
            if let Some(op) = maybe_op {
                let operation_id = op.operation_id.clone().unwrap_or_else(|| {
                    auto_generate_operation_id(&method.to_lowercase(), path_str)
                });
                let description = build_description(op);
                ops.push(OperationSummary {
                    operation_id,
                    method: method.to_string(),
                    path: path_str.clone(),
                    description,
                    tags: op.tags.clone(),
                });
            }
        }
    }

    ops
}

/// Get the base URL from the spec's servers list.
pub fn spec_base_url(spec: &OpenAPI) -> Option<String> {
    spec.servers.first().map(|s| s.url.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PETSTORE_JSON: &str = r#"{
        "openapi": "3.0.3",
        "info": { "title": "Petstore", "version": "1.0.0" },
        "paths": {
            "/pet/{petId}": {
                "get": {
                    "operationId": "getPetById",
                    "summary": "Find pet by ID",
                    "tags": ["pet"],
                    "parameters": [
                        {
                            "name": "petId",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "integer" }
                        }
                    ],
                    "responses": { "200": { "description": "OK" } }
                }
            },
            "/pet": {
                "post": {
                    "operationId": "addPet",
                    "summary": "Add a new pet",
                    "tags": ["pet"],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name"],
                                    "properties": {
                                        "name": { "type": "string", "description": "Pet name" },
                                        "status": { "type": "string", "enum": ["available", "pending", "sold"] }
                                    }
                                }
                            }
                        }
                    },
                    "responses": { "200": { "description": "OK" } }
                },
                "get": {
                    "operationId": "listPets",
                    "summary": "List all pets",
                    "tags": ["pet"],
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": { "type": "integer", "default": 20 }
                        },
                        {
                            "name": "status",
                            "in": "query",
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": { "200": { "description": "OK" } }
                }
            },
            "/store/order": {
                "post": {
                    "operationId": "placeOrder",
                    "summary": "Place an order",
                    "tags": ["store"],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "petId": { "type": "integer" },
                                        "quantity": { "type": "integer" }
                                    }
                                }
                            }
                        }
                    },
                    "responses": { "200": { "description": "OK" } }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "api_key": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Api-Key"
                }
            }
        }
    }"#;

    #[test]
    fn test_parse_spec() {
        let spec = parse_spec(PETSTORE_JSON).unwrap();
        assert_eq!(spec.info.title, "Petstore");
    }

    #[test]
    fn test_extract_tools_no_filter() {
        let spec = parse_spec(PETSTORE_JSON).unwrap();
        let filters = OpenApiFilters {
            include_tags: vec![],
            exclude_tags: vec![],
            include_operations: vec![],
            exclude_operations: vec![],
            max_operations: None,
        };
        let tools = extract_tools(&spec, &filters);
        assert_eq!(tools.len(), 4); // getPetById, addPet, listPets, placeOrder
    }

    #[test]
    fn test_extract_tools_include_tags() {
        let spec = parse_spec(PETSTORE_JSON).unwrap();
        let filters = OpenApiFilters {
            include_tags: vec!["pet".to_string()],
            exclude_tags: vec![],
            include_operations: vec![],
            exclude_operations: vec![],
            max_operations: None,
        };
        let tools = extract_tools(&spec, &filters);
        assert_eq!(tools.len(), 3); // Only pet-tagged operations
        assert!(tools.iter().all(|t| t.tags.contains(&"pet".to_string())));
    }

    #[test]
    fn test_extract_tools_exclude_operations() {
        let spec = parse_spec(PETSTORE_JSON).unwrap();
        let filters = OpenApiFilters {
            include_tags: vec![],
            exclude_tags: vec![],
            include_operations: vec![],
            exclude_operations: vec!["placeOrder".to_string()],
            max_operations: None,
        };
        let tools = extract_tools(&spec, &filters);
        assert_eq!(tools.len(), 3);
        assert!(!tools.iter().any(|t| t.operation_id == "placeOrder"));
    }

    #[test]
    fn test_extract_tools_max_operations() {
        let spec = parse_spec(PETSTORE_JSON).unwrap();
        let filters = OpenApiFilters {
            include_tags: vec![],
            exclude_tags: vec![],
            include_operations: vec![],
            exclude_operations: vec![],
            max_operations: Some(2),
        };
        let tools = extract_tools(&spec, &filters);
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn test_to_ati_tool() {
        let spec = parse_spec(PETSTORE_JSON).unwrap();
        let filters = OpenApiFilters {
            include_tags: vec![],
            exclude_tags: vec![],
            include_operations: vec!["getPetById".to_string()],
            exclude_operations: vec![],
            max_operations: None,
        };
        let tools = extract_tools(&spec, &filters);
        assert_eq!(tools.len(), 1);

        let overrides = HashMap::new();
        let tool = to_ati_tool(tools[0].clone(), "petstore", &overrides);

        assert_eq!(tool.name, "petstore__getPetById");
        assert!(tool.description.contains("Find pet by ID"));
        assert_eq!(tool.endpoint, "/pet/{petId}");
        assert!(tool.input_schema.is_some());
    }

    #[test]
    fn test_to_ati_tool_with_override() {
        let spec = parse_spec(PETSTORE_JSON).unwrap();
        let filters = OpenApiFilters {
            include_tags: vec![],
            exclude_tags: vec![],
            include_operations: vec!["getPetById".to_string()],
            exclude_operations: vec![],
            max_operations: None,
        };
        let tools = extract_tools(&spec, &filters);

        let mut overrides = HashMap::new();
        overrides.insert(
            "getPetById".to_string(),
            OpenApiToolOverride {
                hint: Some("Use this to fetch pet details".into()),
                description: Some("Custom description".into()),
                tags: vec!["custom-tag".into()],
                ..Default::default()
            },
        );

        let tool = to_ati_tool(tools[0].clone(), "petstore", &overrides);
        assert_eq!(tool.description, "Custom description");
        assert_eq!(tool.hint.as_deref(), Some("Use this to fetch pet details"));
        assert!(tool.tags.contains(&"custom-tag".to_string()));
    }

    #[test]
    fn test_detect_auth_api_key_header() {
        let spec = parse_spec(PETSTORE_JSON).unwrap();
        let (auth_type, extra) = detect_auth(&spec);
        assert_eq!(auth_type, "header");
        assert_eq!(extra.get("auth_header_name").unwrap(), "X-Api-Key");
    }

    #[test]
    fn test_auto_generate_operation_id() {
        assert_eq!(
            auto_generate_operation_id("get", "/pet/{petId}"),
            "get_pet_petId"
        );
        assert_eq!(
            auto_generate_operation_id("post", "/store/order"),
            "post_store_order"
        );
    }

    #[test]
    fn test_input_schema_has_params() {
        let spec = parse_spec(PETSTORE_JSON).unwrap();
        let filters = OpenApiFilters {
            include_tags: vec![],
            exclude_tags: vec![],
            include_operations: vec!["listPets".to_string()],
            exclude_operations: vec![],
            max_operations: None,
        };
        let tools = extract_tools(&spec, &filters);
        assert_eq!(tools.len(), 1);

        let schema = &tools[0].input_schema;
        let props = schema.get("properties").unwrap().as_object().unwrap();
        assert!(props.contains_key("limit"));
        assert!(props.contains_key("status"));

        // Verify default value is preserved
        let limit = props.get("limit").unwrap();
        assert_eq!(limit.get("default"), Some(&json!(20)));
    }

    #[test]
    fn test_request_body_params() {
        let spec = parse_spec(PETSTORE_JSON).unwrap();
        let filters = OpenApiFilters {
            include_tags: vec![],
            exclude_tags: vec![],
            include_operations: vec!["addPet".to_string()],
            exclude_operations: vec![],
            max_operations: None,
        };
        let tools = extract_tools(&spec, &filters);
        assert_eq!(tools.len(), 1);

        let schema = &tools[0].input_schema;
        let props = schema.get("properties").unwrap().as_object().unwrap();
        assert!(props.contains_key("name"));
        assert!(props.contains_key("status"));

        // name should be required
        let required = schema.get("required").unwrap().as_array().unwrap();
        assert!(required.contains(&json!("name")));
    }
}
