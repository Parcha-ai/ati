# Acknowledgments

## OpenAPI Generator

The collection format and parameter serialization handling in ATI's OpenAPI mode
was influenced by the [OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator)
project, licensed under the Apache License, Version 2.0.

Specifically, the approach to serializing array query parameters using
`style`/`explode` fields (multi, csv, ssv, pipes) and the handling of
`application/x-www-form-urlencoded` request bodies drew from patterns established
in OpenAPI Generator's bash client code generation.

OpenAPI Generator is copyright the OpenAPI Generator contributors.
See https://github.com/OpenAPITools/openapi-generator/blob/master/LICENSE for
the full license text.

## OpenAPI Specification

ATI implements the [OpenAPI Specification 3.0](https://spec.openapis.org/oas/v3.0.3),
developed by the OpenAPI Initiative under the Linux Foundation.
