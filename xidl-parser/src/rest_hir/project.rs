use crate::error::{ParseError, ParserResult};
use crate::hir;
use std::collections::HashSet;

use super::attr::project_attribute;
use super::mapping;
use super::model::{HttpException, HttpExceptionRef, HttpRepresentation, HttpUnion};
use super::project_params::project_params;
use super::route::{
    auto_default_method_path, operation_id, parse_route_template, route_from_annotations,
};
use super::semantics::{
    HttpStreamKind, UpgradeMode, classify_upgrade_protocol, effective_cors, effective_media_type,
    effective_security_with_origin, has_annotation, http_stream_config, parse_upgrade_protocol,
    parse_websocket_config, validate_http_annotations,
};
use super::validate::{
    effective_basic_auth_realm, effective_deprecated, validate_head_constraints,
    validate_request_shape, validate_route_bindings, validate_stream_method, validate_stream_shape,
    validate_upgrade_constraints, validate_websocket_stream_items,
};
use super::{
    HttpDocumentMetadata, HttpDocumentServer, HttpInterface, HttpOperation, HttpOperationMeta,
    HttpOperationSource, RestHirDocument,
};

pub fn project(spec: &hir::Specification) -> ParserResult<RestHirDocument> {
    let mut ctx = ProjectionContext::default();
    // Exceptions and `@http` unions first: operations resolve against them.
    ctx.collect_exceptions(&spec.0, &[])?;
    let mut http_enums = Vec::new();
    collect_http_enums(&spec.0, &[], &mut http_enums);
    let http_unions = collect_http_unions(&spec.0, &[], &http_enums)?;
    ctx.document.http_unions = http_unions;
    ctx.collect_spec(spec, &[])?;
    ctx.document.exceptions = ctx.exceptions;
    Ok(RestHirDocument {
        spec: spec.clone(),
        document: ctx.document,
        interfaces: ctx.interfaces,
    })
}

fn parse_err(message: String) -> ParseError {
    ParseError::Message(message)
}

#[derive(Default)]
struct ProjectionContext {
    document: HttpDocumentMetadata,
    exceptions: Vec<HttpException>,
    interfaces: Vec<HttpInterface>,
}

impl ProjectionContext {
    fn collect_exceptions(
        &mut self,
        definitions: &[hir::Definition],
        module_path: &[String],
    ) -> ParserResult<()> {
        for def in definitions {
            match def {
                hir::Definition::ModuleDcl(module) => {
                    let mut next = module_path.to_vec();
                    next.push(module.ident.clone());
                    self.collect_exceptions(&module.definition, &next)?;
                }
                hir::Definition::ExceptDcl(except) => {
                    self.exceptions
                        .push(HttpException::from_hir(except, module_path)?);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn collect_spec(
        &mut self,
        spec: &hir::Specification,
        module_path: &[String],
    ) -> ParserResult<()> {
        for def in &spec.0 {
            self.collect_def(def, module_path)?;
        }
        Ok(())
    }

    fn collect_def(&mut self, def: &hir::Definition, module_path: &[String]) -> ParserResult<()> {
        match def {
            hir::Definition::ModuleDcl(module) => {
                let mut next = module_path.to_vec();
                next.push(module.ident.clone());
                for def in &module.definition {
                    self.collect_def(def, &next)?;
                }
            }
            hir::Definition::Pragma(pragma) => self.apply_pragma(pragma),
            hir::Definition::InterfaceDcl(interface) => {
                if let Some(interface) = project_interface(
                    interface,
                    module_path,
                    &self.exceptions,
                    &self.document.http_unions,
                )? {
                    self.interfaces.push(interface);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn apply_pragma(&mut self, pragma: &hir::Pragma) {
        match pragma {
            hir::Pragma::XidlcPackage(value) if !value.is_empty() => {
                self.document.package = Some(normalize_pragma_scalar(value));
            }
            hir::Pragma::XidlcOpenApiVersion(value) if !value.is_empty() => {
                self.document.version = Some(normalize_pragma_scalar(value));
            }
            hir::Pragma::XidlcOpenApiService {
                base_url,
                description,
            } if !base_url.is_empty() => {
                self.document.servers.push(HttpDocumentServer {
                    base_url: base_url.clone(),
                    description: description.clone(),
                });
            }
            _ => {}
        }
    }
}

fn normalize_pragma_scalar(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('=')
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn project_interface(
    interface: &hir::InterfaceDcl,
    module_path: &[String],
    exceptions: &[HttpException],
    http_unions: &[HttpUnion],
) -> ParserResult<Option<HttpInterface>> {
    let hir::InterfaceDclInner::InterfaceDef(def) = &interface.decl else {
        return Ok(None);
    };
    validate_http_annotations(
        &format!("interface '{}'", def.header.ident),
        &interface.annotations,
    )
    .map_err(ParseError::Message)?;

    let mut operations = Vec::new();
    if let Some(body) = &def.interface_body {
        for export in &body.0 {
            match export {
                hir::Export::OpDcl(op) => operations.push(project_operation(
                    &def.header.ident,
                    module_path,
                    &interface.annotations,
                    exceptions,
                    http_unions,
                    op,
                )?),
                hir::Export::AttrDcl(attr) => operations.extend(project_attribute_group(
                    &def.header.ident,
                    module_path,
                    &interface.annotations,
                    attr,
                )?),
                _ => {}
            }
        }
    }

    Ok(Some(HttpInterface {
        name: def.header.ident.clone(),
        module_path: module_path.to_vec(),
        operations,
    }))
}

fn project_attribute_group(
    interface_name: &str,
    module_path: &[String],
    interface_annotations: &[hir::Annotation],
    attr: &hir::AttrDcl,
) -> ParserResult<Vec<HttpOperation>> {
    validate_http_annotations(
        &format!("attribute in interface '{interface_name}'"),
        &attr.annotations,
    )
    .map_err(ParseError::Message)?;
    if has_annotation(&attr.annotations, "cors") {
        return Err(ParseError::Message(format!(
            "attribute in interface '{interface_name}': @cors is only supported on interfaces and methods"
        )));
    }
    let cors = effective_cors(interface_annotations, &[]).map_err(ParseError::Message)?;
    let deprecated = effective_deprecated(interface_annotations, &attr.annotations)
        .map_err(ParseError::Message)?;
    let security = effective_security_with_origin(interface_annotations, &attr.annotations)
        .map_err(ParseError::Message)?;
    let mut operations = project_attribute(
        interface_name,
        module_path,
        attr,
        security,
        deprecated,
        has_annotation(&attr.annotations, "server_stream"),
    );
    for operation in &mut operations {
        operation.meta.cors = cors.clone();
    }
    Ok(operations)
}

fn project_operation(
    interface_name: &str,
    module_path: &[String],
    interface_annotations: &[hir::Annotation],
    exceptions: &[HttpException],
    http_unions: &[HttpUnion],
    op: &hir::OpDcl,
) -> ParserResult<HttpOperation> {
    validate_http_annotations(&format!("operation '{}'", op.ident), &op.annotations)
        .map_err(ParseError::Message)?;
    let mut stream = http_stream_config(&op.annotations).map_err(ParseError::Message)?;
    validate_stream_shape(&op.ident, stream).map_err(parse_err)?;
    let has_upgrade = has_annotation(&op.annotations, "upgrade");
    let has_stream_annotation = has_annotation(&op.annotations, "server_stream")
        || has_annotation(&op.annotations, "client_stream")
        || has_annotation(&op.annotations, "bidi_stream");
    if has_upgrade && has_stream_annotation {
        return Err(parse_err(
            "@upgrade cannot be combined with @server_stream/@client_stream/@bidi_stream"
                .to_string(),
        ));
    }

    let upgrade_protocol = parse_upgrade_protocol(&op.annotations).map_err(parse_err)?;
    let upgrade_mode = upgrade_protocol
        .as_deref()
        .map(classify_upgrade_protocol)
        .transpose()
        .map_err(parse_err)?;
    let websocket = match upgrade_mode {
        Some(mode) => parse_websocket_config(&op.annotations, mode).map_err(parse_err)?,
        None => None,
    };
    // WebSocket mode is projected as a bidirectional stream plus WS config.
    if upgrade_mode == Some(UpgradeMode::WebSocket) {
        stream.kind = Some(HttpStreamKind::Bidi);
    }

    let default_method = if matches!(
        stream.kind,
        Some(HttpStreamKind::Server) | Some(HttpStreamKind::Bidi)
    ) || has_upgrade
    {
        super::HttpMethod::Get
    } else {
        super::HttpMethod::Post
    };
    let (method, mut route_paths) =
        route_from_annotations(&op.annotations, default_method).map_err(parse_err)?;
    validate_stream_method(&op.ident, stream.kind, method).map_err(parse_err)?;
    if route_paths.is_empty() {
        route_paths.push(auto_default_method_path(op, method).map_err(parse_err)?);
    }
    let routes = route_paths
        .iter()
        .map(|path| parse_route_template(path).map_err(parse_err))
        .collect::<ParserResult<Vec<_>>>()?;
    let route_path_names = routes
        .iter()
        .map(|route| route.path_params.iter().cloned().collect::<HashSet<_>>())
        .collect::<Vec<_>>();
    let route_query_names = routes
        .iter()
        .map(|route| route.query_params.iter().cloned().collect::<HashSet<_>>())
        .collect::<Vec<_>>();

    let (request_params, response_params, path_binding_count, query_binding_count) =
        project_params(
            op,
            method,
            stream.kind,
            &route_path_names,
            &route_query_names,
        )
        .map_err(parse_err)?;

    validate_route_bindings(
        &op.ident,
        &routes,
        &path_binding_count,
        &query_binding_count,
    )
    .map_err(parse_err)?;
    let allow_handshake_params = upgrade_mode == Some(UpgradeMode::WebSocket);
    validate_request_shape(
        &op.ident,
        stream.kind,
        &request_params,
        allow_handshake_params,
    )
    .map_err(parse_err)?;
    validate_head_constraints(
        &op.ident,
        method,
        &response_params,
        match &op.ty {
            hir::OpTypeSpec::Void => None,
            hir::OpTypeSpec::TypeSpec(ty) => Some(ty),
        },
    )
    .map_err(parse_err)?;

    validate_upgrade_constraints(
        &op.ident,
        upgrade_mode,
        method,
        &request_params,
        match &op.ty {
            hir::OpTypeSpec::Void => None,
            hir::OpTypeSpec::TypeSpec(ty) => Some(ty),
        },
    )
    .map_err(parse_err)?;
    if upgrade_mode == Some(UpgradeMode::WebSocket) {
        validate_websocket_stream_items(&op.ident, &request_params, &response_params)
            .map_err(parse_err)?;
    }

    let request_content_type =
        effective_media_type(interface_annotations, &op.annotations, "request");
    let response_content_type =
        effective_media_type(interface_annotations, &op.annotations, "response");
    let cors =
        effective_cors(interface_annotations, &op.annotations).map_err(ParseError::Message)?;
    let security = effective_security_with_origin(interface_annotations, &op.annotations)
        .map_err(ParseError::Message)?;
    let basic_auth_realm = effective_basic_auth_realm(interface_annotations, &op.annotations);
    let deprecated = effective_deprecated(interface_annotations, &op.annotations)
        .map_err(ParseError::Message)?;

    let return_type = match &op.ty {
        hir::OpTypeSpec::Void => None,
        hir::OpTypeSpec::TypeSpec(ty) => Some(ty.clone()),
    };

    let signature = mapping::build_operation_signature(op);
    let http = mapping::build_http_mapping(
        method,
        &stream,
        request_content_type.as_deref(),
        response_content_type.as_deref(),
        &request_params,
        &response_params,
        &return_type,
    );
    if op.raises.is_some() && (stream.kind.is_some() || has_upgrade) {
        return Err(ParseError::Message(format!(
            "operation '{}': raises(...) is only supported on non-stream, non-upgrade operations",
            op.ident
        )));
    }
    let raises = HttpExceptionRef::for_operation(op, module_path, exceptions)?;
    let representations = project_representations(
        &op.ident,
        module_path,
        http_unions,
        stream.kind,
        has_upgrade,
        &return_type,
    )?;

    Ok(HttpOperation {
        meta: HttpOperationMeta {
            name: op.ident.clone(),
            operation_id: operation_id(module_path, interface_name, &op.ident),
            source: HttpOperationSource::Method,
            method,
            routes,
            stream,
            cors,
            security,
            basic_auth_realm,
            deprecated,
            upgrade_protocol,
            upgrade_mode,
            websocket,
            raises,
        },
        signature,
        http: {
            let mut http = http;
            http.response.representations = representations;
            http
        },
    })
}

/// Collects every enum declaration so `@http` unions can resolve their
/// switch discriminator and derive member media types.
fn collect_http_enums(
    definitions: &[hir::Definition],
    module_path: &[String],
    out: &mut Vec<(Vec<String>, hir::EnumDcl)>,
) {
    for def in definitions {
        match def {
            hir::Definition::ModuleDcl(module) => {
                let mut next = module_path.to_vec();
                next.push(module.ident.clone());
                collect_http_enums(&module.definition, &next, out);
            }
            hir::Definition::TypeDcl(hir::TypeDcl::ConstrTypeDcl(hir::ConstrTypeDcl::EnumDcl(
                enum_dcl,
            ))) => out.push((module_path.to_vec(), enum_dcl.clone())),
            _ => {}
        }
    }
}

/// Collects `@http` unions with their content-negotiated cases resolved.
fn collect_http_unions(
    definitions: &[hir::Definition],
    module_path: &[String],
    http_enums: &[(Vec<String>, hir::EnumDcl)],
) -> ParserResult<Vec<HttpUnion>> {
    let mut out = Vec::new();
    fn walk(
        definitions: &[hir::Definition],
        module_path: &[String],
        http_enums: &[(Vec<String>, hir::EnumDcl)],
        out: &mut Vec<HttpUnion>,
    ) -> ParserResult<()> {
        for def in definitions {
            match def {
                hir::Definition::ModuleDcl(module) => {
                    let mut next = module_path.to_vec();
                    next.push(module.ident.clone());
                    walk(&module.definition, &next, http_enums, out)?;
                }
                hir::Definition::TypeDcl(hir::TypeDcl::ConstrTypeDcl(
                    hir::ConstrTypeDcl::UnionDef(union),
                )) => {
                    if has_annotation(&union.annotations, "http") {
                        out.push(HttpUnion {
                            module_path: module_path.to_vec(),
                            ident: union.ident.clone(),
                            cases: http_union_cases(union, module_path, http_enums)?,
                        });
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
    walk(definitions, module_path, http_enums, &mut out)?;
    Ok(out)
}

fn http_union_cases(
    union: &hir::UnionDef,
    module_path: &[String],
    http_enums: &[(Vec<String>, hir::EnumDcl)],
) -> ParserResult<Vec<HttpRepresentation>> {
    let hir::SwitchTypeSpec::ScopedName(scoped) = &union.switch_type_spec else {
        return Err(parse_err(format!(
            "@http union '{}': the switch discriminator must be an enum",
            union.ident
        )));
    };
    let enum_def = resolve_scoped_definition(
        http_enums
            .iter()
            .map(|(path, enum_dcl)| (path.as_slice(), enum_dcl)),
        module_path,
        scoped,
        |enum_dcl| enum_dcl.ident.as_str(),
    )
    .ok_or_else(|| {
        parse_err(format!(
            "@http union '{}': switch enum '{}' does not resolve",
            union.ident,
            scoped.name.join("::")
        ))
    })?;
    let mut cases = Vec::new();
    for case in &union.case {
        if case.label.len() != 1
            || case
                .label
                .iter()
                .any(|label| matches!(label, hir::CaseLabel::Default))
        {
            return Err(parse_err(format!(
                "@http union '{}': every case needs exactly one enum-member label (no default)",
                union.ident
            )));
        }
        for label in &case.label {
            let hir::CaseLabel::Value(hir::ConstExpr::ScopedName(label_name)) = label else {
                return Err(parse_err(format!(
                    "@http union '{}': case labels must name enum members",
                    union.ident
                )));
            };
            let case_ident = label_name.name.last().cloned().ok_or_else(|| {
                parse_err(format!("@http union '{}': empty case label", union.ident))
            })?;
            let enumerator = enum_def
                .member
                .iter()
                .find(|member| member.ident == case_ident)
                .ok_or_else(|| {
                    parse_err(format!(
                        "@http union '{}': case label '{}' is not a member of enum '{}'",
                        union.ident, case_ident, enum_def.ident
                    ))
                })?;
            let content_type = hir::field_rename(&enumerator.annotations)
                .or_else(|| well_known_media_type(&enumerator.ident))
                .ok_or_else(|| {
                    parse_err(format!(
                        "@http union '{}': cannot derive a media type from enum member '{}'; add @rename(\"...\") to it",
                        union.ident, enumerator.ident
                    ))
                })?;
            let ty = match &case.element.ty {
                hir::ElementSpecTy::TypeSpec(ty) => ty.clone(),
                hir::ElementSpecTy::ConstrTypeDcl(_) => {
                    return Err(parse_err(format!(
                        "@http union '{}': case '{}'-payloads must use named types",
                        union.ident, case_ident
                    )));
                }
            };
            cases.push(HttpRepresentation {
                case: case_ident,
                content_type,
                is_byte: is_byte_sequence(&ty),
                ty,
            });
        }
    }
    Ok(cases)
}

fn is_byte_sequence(ty: &hir::TypeSpec) -> bool {
    matches!(
        ty,
        hir::TypeSpec::SequenceType(seq) if matches!(&*seq.ty, hir::TypeSpec::IntegerType(hir::IntegerType::Octet))
    )
}

/// Well-known media types derivable from an enum member name; anything
/// else needs an explicit `@rename`.
fn well_known_media_type(ident: &str) -> Option<String> {
    match ident.to_ascii_lowercase().as_str() {
        "json" => Some("application/json".to_string()),
        "octetstream" | "binary" | "bytes" => Some("application/octet-stream".to_string()),
        "text" | "textplain" | "plaintext" => Some("text/plain".to_string()),
        "xml" => Some("application/xml".to_string()),
        "html" => Some("text/html".to_string()),
        "msgpack" => Some("application/msgpack".to_string()),
        "form" | "urlencoded" | "formurlencoded" => {
            Some("application/x-www-form-urlencoded".to_string())
        }
        _ => None,
    }
}

/// Resolves a (module path, identifier) pair for a scoped name written
/// inside `module_path`, walking outward through enclosing modules.
fn resolve_scoped_definition<'a, T>(
    items: impl Iterator<Item = (&'a [String], &'a T)>,
    module_path: &[String],
    scoped: &hir::ScopedName,
    ident_of: impl Fn(&T) -> &str,
) -> Option<&'a T> {
    let ident = scoped.name.last()?;
    let prefix = &scoped.name[..scoped.name.len() - 1];
    let items: Vec<(&'a [String], &'a T)> = items.collect();
    if scoped.is_root {
        return items
            .into_iter()
            .find(|(path, item)| *path == prefix && ident_of(item) == &ident[..])
            .map(|(_, item)| item);
    }
    for skip in (0..=module_path.len()).rev() {
        let scope = &module_path[..skip];
        if scope.ends_with(prefix)
            && let Some(found) = items
                .iter()
                .find(|(path, item)| *path == scope && ident_of(item) == &ident[..])
                .map(|(_, item)| *item)
        {
            return Some(found);
        }
    }
    None
}

fn project_representations(
    op_ident: &str,
    module_path: &[String],
    http_unions: &[HttpUnion],
    stream_kind: Option<HttpStreamKind>,
    has_upgrade: bool,
    return_type: &Option<hir::TypeSpec>,
) -> ParserResult<Vec<HttpRepresentation>> {
    let Some(hir::TypeSpec::ScopedName(scoped)) = return_type else {
        return Ok(Vec::new());
    };
    let items = http_unions.iter().map(|u| (u.module_path.as_slice(), u));
    let union = resolve_scoped_definition(items, module_path, scoped, |u| u.ident.as_str());
    let Some(union) = union else {
        return Ok(Vec::new());
    };
    if union.cases.is_empty() {
        return Ok(Vec::new());
    }
    if stream_kind.is_some() || has_upgrade {
        return Err(parse_err(format!(
            "operation '{op_ident}': @http union return types are only supported on non-stream, non-upgrade operations"
        )));
    }
    let mut seen = HashSet::new();
    for case in &union.cases {
        if !seen.insert(case.content_type.clone()) {
            return Err(parse_err(format!(
                "operation '{op_ident}': @http union '{}' declares duplicate media type '{}'",
                union.ident, case.content_type
            )));
        }
    }
    Ok(union.cases.clone())
}
