// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Translate a SystemRDL AST into the reggen [`schema`](crate::schema).
//!
//! Walks the RDL `Root` and extracts:
//! - `addrmap` instances → [`RegisterBlock`](crate::schema::RegisterBlock)
//! - `reg` definitions → [`Register`](crate::schema::Register)
//! - `field` definitions → [`Field`](crate::schema::Field)

use anyhow::Context;
use anyhow::Result;
use azihsm_systemrdl::ast;

use crate::schema::BlockItem;
use crate::schema::Field;
use crate::schema::FieldAccess;
use crate::schema::RegFile;
use crate::schema::Register;
use crate::schema::RegisterBlock;
use crate::schema::SocSchema;

/// Translate a parsed RDL root into a [`SocSchema`].
///
/// The top-level `addrmap` is expected to contain `addrmap` instances
/// (one per peripheral), each containing `reg` instances with `field`s.
pub fn from_ast(root: &ast::Root, soc_name: &str) -> Result<SocSchema> {
    let mut blocks = Vec::new();

    for desc in &root.descriptions {
        if let ast::Description::ComponentDef(component) = desc {
            if let ast::ComponentDef::Named(ast::ComponentType::AddrMap, name, _, body) =
                &component.def
            {
                // Top-level addrmap — look for sub-addrmaps (peripherals)
                if let Some(insts) = &component.insts {
                    // Instantiated at top level with address
                    let base = extract_base_addr(insts);
                    let block = translate_addrmap(name, base, body, root)?;
                    blocks.push(block);
                } else {
                    // Inline addrmap — scan body for instantiated sub-addrmaps
                    for elem in &body.elements {
                        if let ast::ComponentBodyElem::ExplicitComponentInst(inst) = elem {
                            let base = extract_inst_base_addr(inst);
                            // Find the addrmap definition for this instance
                            if let Some(block) =
                                find_and_translate_addrmap(&inst.id, base, root, body)?
                            {
                                blocks.push(block);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(SocSchema {
        name: soc_name.to_string(),
        blocks,
    })
}

/// Find an addrmap definition by name and translate it.
fn find_and_translate_addrmap(
    type_name: &str,
    base: u32,
    root: &ast::Root,
    parent_body: &ast::ComponentBody,
) -> Result<Option<RegisterBlock>> {
    // Search in parent body first (nested definitions)
    for elem in &parent_body.elements {
        if let ast::ComponentBodyElem::ComponentDef(comp) = elem {
            if let ast::ComponentDef::Named(ast::ComponentType::AddrMap, name, _, body) = &comp.def
            {
                if name == type_name {
                    return Ok(Some(translate_addrmap(name, base, body, root)?));
                }
            }
        }
    }
    // Search in root descriptions
    for desc in &root.descriptions {
        if let ast::Description::ComponentDef(comp) = desc {
            if let ast::ComponentDef::Named(ast::ComponentType::AddrMap, name, _, body) = &comp.def
            {
                if name == type_name {
                    return Ok(Some(translate_addrmap(name, base, body, root)?));
                }
            }
        }
    }
    Ok(None)
}

/// Translate a single addrmap into a RegisterBlock.
fn translate_addrmap(
    name: &str,
    base: u32,
    body: &ast::ComponentBody,
    root: &ast::Root,
) -> Result<RegisterBlock> {
    let mut items = Vec::new();
    let mut desc = String::new();

    for elem in &body.elements {
        match elem {
            ast::ComponentBodyElem::ExplicitComponentInst(inst) => {
                let offset = extract_inst_base_addr(inst);
                let array_count = extract_inst_array_count(inst);
                let stride = extract_inst_stride(inst);
                let inst_name = extract_inst_name(inst);

                // Try as a reg first
                if let Some(mut reg) = find_and_translate_reg(&inst.id, offset, body, root)? {
                    if let Some(name) = &inst_name {
                        reg.name = name.clone();
                    }
                    reg.count = array_count;
                    items.push(BlockItem::Reg(reg));
                } else if let Some(rf) = find_and_translate_regfile(
                    &inst.id,
                    offset,
                    array_count,
                    stride,
                    &inst_name,
                    body,
                    root,
                )? {
                    items.push(BlockItem::RegFile(rf));
                } else if let Some(mem) = find_and_translate_mem(
                    &inst.id,
                    offset,
                    array_count,
                    stride,
                    &inst_name,
                    body,
                    root,
                )? {
                    items.push(BlockItem::Mem(mem));
                }
            }
            ast::ComponentBodyElem::PropertyAssignment(pa) => {
                if let Some(d) = extract_desc_from_property(pa) {
                    desc = d;
                }
            }
            _ => {}
        }
    }

    items.sort_by_key(|item| item.offset());

    Ok(RegisterBlock {
        name: to_snake_case(name),
        base_addr: base,
        items,
        desc,
    })
}

/// Find a reg definition by type name and translate it.
fn find_and_translate_reg(
    type_name: &str,
    offset: u32,
    parent_body: &ast::ComponentBody,
    root: &ast::Root,
) -> Result<Option<Register>> {
    // Search in parent body
    for elem in &parent_body.elements {
        if let ast::ComponentBodyElem::ComponentDef(comp) = elem {
            if let ast::ComponentDef::Named(ast::ComponentType::Reg, name, _, body) = &comp.def {
                if name == type_name {
                    return Ok(Some(
                        translate_reg(name, offset, body).context("translating reg")?,
                    ));
                }
            }
        }
    }
    // Search in root
    for desc in &root.descriptions {
        if let ast::Description::ComponentDef(comp) = desc {
            if let ast::ComponentDef::Named(ast::ComponentType::Reg, name, _, body) = &comp.def {
                if name == type_name {
                    return Ok(Some(
                        translate_reg(name, offset, body).context("translating reg")?,
                    ));
                }
            }
        }
    }
    Ok(None)
}

/// Translate a single reg into a Register.
fn translate_reg(name: &str, offset: u32, body: &ast::ComponentBody) -> Result<Register> {
    let mut fields = Vec::new();
    let mut desc = String::new();
    let mut sw_access = FieldAccess::RW;

    for elem in &body.elements {
        match elem {
            ast::ComponentBodyElem::ComponentDef(comp) => {
                if let ast::ComponentDef::Anon(ast::ComponentType::Field, field_body) = &comp.def {
                    if let Some(insts) = &comp.insts {
                        for ci in &insts.component_insts {
                            let field =
                                translate_field(&ci.id, field_body, sw_access, &ci.array_or_range)?;
                            fields.push(field);
                        }
                    }
                }
            }
            ast::ComponentBodyElem::PropertyAssignment(pa) => {
                if let Some(d) = extract_desc_from_property(pa) {
                    desc = d;
                }
                if let Some(access) = extract_sw_from_property(pa) {
                    sw_access = access;
                }
            }
            _ => {}
        }
    }

    // Second pass: apply post-property assignments (FIELD_NAME->sw = value; or FIELD->woclr;)
    for elem in &body.elements {
        if let ast::ComponentBodyElem::PropertyAssignment(pa) = elem {
            if let Some((field_name, access)) = extract_post_prop_sw(pa) {
                for field in &mut fields {
                    if field.name.eq_ignore_ascii_case(&field_name) {
                        field.access = access;
                    }
                }
            }
            if let Some(field_name) = extract_post_prop_woclr(pa) {
                for field in &mut fields {
                    if field.name.eq_ignore_ascii_case(&field_name) {
                        field.access = FieldAccess::W1C;
                    }
                }
            }
        }
    }

    // Strip the _t suffix from register type names
    let reg_name = name.strip_suffix("_t").unwrap_or(name);

    Ok(Register {
        name: reg_name.to_uppercase(),
        offset,
        fields,
        desc,
        count: None,
    })
}

/// Translate a field definition.
fn translate_field(
    name: &str,
    body: &ast::ComponentBody,
    default_access: FieldAccess,
    range: &Option<ast::ArrayOrRange>,
) -> Result<Field> {
    let (offset, width) = match range {
        Some(ast::ArrayOrRange::Range(ast::Range::Range(hi, lo))) => {
            let hi = eval_const_expr(hi);
            let lo = eval_const_expr(lo);
            (lo as u32, (hi - lo + 1) as u32)
        }
        _ => (0, 1),
    };

    let mut access = default_access;
    let mut desc = String::new();
    let reset = 0u64;

    for elem in &body.elements {
        if let ast::ComponentBodyElem::PropertyAssignment(pa) = elem {
            if let Some(a) = extract_sw_from_property(pa) {
                access = a;
            }
            if let Some(d) = extract_desc_from_property(pa) {
                desc = d;
            }
            // Check for W1C via onwrite property
            if let Some(a) = extract_onwrite_access(pa) {
                access = a;
            }
        }
    }

    Ok(Field {
        name: name.to_uppercase(),
        offset,
        width,
        access,
        reset,
        desc,
    })
}

/// Find a regfile definition by type name and translate it.
fn find_and_translate_regfile(
    type_name: &str,
    offset: u32,
    array_count: Option<u32>,
    stride: Option<u32>,
    inst_name: &Option<String>,
    parent_body: &ast::ComponentBody,
    root: &ast::Root,
) -> Result<Option<RegFile>> {
    // Search in parent body
    for elem in &parent_body.elements {
        if let ast::ComponentBodyElem::ComponentDef(comp) = elem {
            if let ast::ComponentDef::Named(ast::ComponentType::RegFile, name, _, body) = &comp.def
            {
                if name == type_name {
                    return Ok(Some(translate_regfile(
                        name,
                        offset,
                        array_count,
                        stride,
                        inst_name,
                        body,
                        parent_body,
                        root,
                    )?));
                }
            }
        }
    }
    // Search in root
    for desc in &root.descriptions {
        if let ast::Description::ComponentDef(comp) = desc {
            if let ast::ComponentDef::Named(ast::ComponentType::RegFile, name, _, body) = &comp.def
            {
                if name == type_name {
                    return Ok(Some(translate_regfile(
                        name,
                        offset,
                        array_count,
                        stride,
                        inst_name,
                        body,
                        parent_body,
                        root,
                    )?));
                }
            }
        }
    }
    Ok(None)
}

/// Translate a regfile definition into a RegFile schema entry.
#[allow(clippy::too_many_arguments)]
fn translate_regfile(
    type_name: &str,
    offset: u32,
    array_count: Option<u32>,
    stride: Option<u32>,
    inst_name: &Option<String>,
    body: &ast::ComponentBody,
    parent_body: &ast::ComponentBody,
    root: &ast::Root,
) -> Result<RegFile> {
    let mut children = Vec::new();
    let mut desc = String::new();

    for elem in &body.elements {
        match elem {
            ast::ComponentBodyElem::ExplicitComponentInst(inst) => {
                let child_offset = extract_inst_base_addr(inst);
                let child_name = extract_inst_name(inst);
                // Only support reg children (not nested regfiles)
                if let Some(mut reg) = find_and_translate_reg(&inst.id, child_offset, body, root)? {
                    if reg.name
                        == inst
                            .id
                            .strip_suffix("_t")
                            .unwrap_or(&inst.id)
                            .to_uppercase()
                    {
                        // If no instance rename, try parent body for the reg definition
                    }
                    if let Some(name) = child_name {
                        reg.name = name;
                    }
                    children.push(reg);
                } else {
                    // Also search the parent body for the reg type definition
                    if let Some(mut reg) =
                        find_and_translate_reg(&inst.id, child_offset, parent_body, root)?
                    {
                        if let Some(name) = child_name {
                            reg.name = name;
                        }
                        children.push(reg);
                    }
                }
            }
            ast::ComponentBodyElem::PropertyAssignment(pa) => {
                if let Some(d) = extract_desc_from_property(pa) {
                    desc = d;
                }
            }
            _ => {}
        }
    }

    children.sort_by_key(|r| r.offset);

    // Compute entry size from children
    let entry_size = children.iter().map(|r| r.offset + 4).max().unwrap_or(0);

    let count = array_count.unwrap_or(1);
    let actual_stride = stride.unwrap_or(entry_size);

    // Strip _t suffix from type name
    let clean_type = type_name.strip_suffix("_t").unwrap_or(type_name);

    let name = inst_name
        .clone()
        .unwrap_or_else(|| clean_type.to_uppercase());

    Ok(RegFile {
        name,
        type_name: to_snake_case(clean_type),
        offset,
        stride: actual_stride,
        count,
        children,
        desc,
    })
}

/// Find a mem definition by type name and translate it into a `MemRegion`.
///
/// SystemRDL `mem` components use `mementries` (entry count) and `memwidth`
/// (bits per entry) properties to define their size.
fn find_and_translate_mem(
    type_name: &str,
    offset: u32,
    array_count: Option<u32>,
    stride: Option<u32>,
    inst_name: &Option<String>,
    parent_body: &ast::ComponentBody,
    root: &ast::Root,
) -> Result<Option<crate::schema::MemRegion>> {
    // Search in parent body first
    for elem in &parent_body.elements {
        if let ast::ComponentBodyElem::ComponentDef(comp) = elem {
            if let ast::ComponentDef::Named(ast::ComponentType::Mem, name, _, body) = &comp.def {
                if name == type_name {
                    return Ok(Some(translate_mem(
                        name,
                        offset,
                        array_count,
                        stride,
                        inst_name,
                        body,
                    )?));
                }
            }
        }
    }
    // Search in root descriptions
    for desc in &root.descriptions {
        if let ast::Description::ComponentDef(comp) = desc {
            if let ast::ComponentDef::Named(ast::ComponentType::Mem, name, _, body) = &comp.def {
                if name == type_name {
                    return Ok(Some(translate_mem(
                        name,
                        offset,
                        array_count,
                        stride,
                        inst_name,
                        body,
                    )?));
                }
            }
        }
    }
    Ok(None)
}

/// Translate a `mem` component body into a `MemRegion`.
fn translate_mem(
    type_name: &str,
    offset: u32,
    array_count: Option<u32>,
    stride: Option<u32>,
    inst_name: &Option<String>,
    body: &ast::ComponentBody,
) -> Result<crate::schema::MemRegion> {
    let mut mementries: u32 = 0;
    let mut memwidth: u32 = 32; // default: 32 bits
    let mut desc = String::new();

    for elem in &body.elements {
        if let ast::ComponentBodyElem::PropertyAssignment(pa) = elem {
            if let Some(d) = extract_desc_from_property(pa) {
                desc = d;
            }
            if let Some((prop_name, value)) = extract_int_property(pa) {
                match prop_name.as_str() {
                    "mementries" => mementries = value as u32,
                    "memwidth" => memwidth = value as u32,
                    _ => {}
                }
            }
        }
    }

    let entry_size = mementries * (memwidth / 8);
    let count = array_count.unwrap_or(1);
    let actual_stride = stride.unwrap_or(entry_size);

    let clean_type = type_name.strip_suffix("_t").unwrap_or(type_name);
    let name = inst_name
        .clone()
        .unwrap_or_else(|| clean_type.to_uppercase());

    Ok(crate::schema::MemRegion {
        name,
        offset,
        entry_size,
        count,
        stride: actual_stride,
        desc,
    })
}

/// Extract an integer property assignment (e.g., `mementries = 512;`).
fn extract_int_property(pa: &ast::PropertyAssignment) -> Option<(String, u64)> {
    if let ast::PropertyAssignment::ExplicitOrDefaultPropAssignment(
        ast::ExplicitOrDefaultPropAssignment::ExplicitPropAssignment(
            _,
            ast::ExplicitPropertyAssignment::Assignment(
                ast::IdentityOrPropKeyword::Id(id),
                Some(ast::PropAssignmentRhs::ConstantExpr(expr)),
            ),
        ),
    ) = pa
    {
        let value = eval_const_expr(expr);
        return Some((id.clone(), value));
    }
    None
}

// ── Helpers ─────────────────────────────────────────────────────────

fn extract_inst_base_addr(inst: &ast::ExplicitComponentInst) -> u32 {
    for ci in &inst.component_insts.component_insts {
        if let Some(expr) = &ci.at {
            return eval_const_expr(expr) as u32;
        }
    }
    0
}

/// Extract array count from an explicit component instance, if present.
fn extract_inst_array_count(inst: &ast::ExplicitComponentInst) -> Option<u32> {
    for ci in &inst.component_insts.component_insts {
        if let Some(ast::ArrayOrRange::Array(dims)) = &ci.array_or_range {
            if let Some(dim) = dims.first() {
                return Some(eval_const_expr(dim) as u32);
            }
        }
    }
    None
}

/// Extract stride (`+= <expr>`) from an explicit component instance, if present.
fn extract_inst_stride(inst: &ast::ExplicitComponentInst) -> Option<u32> {
    for ci in &inst.component_insts.component_insts {
        if let Some(expr) = &ci.plus_equals {
            return Some(eval_const_expr(expr) as u32);
        }
    }
    None
}

/// Extract the instance name from an explicit component instance.
fn extract_inst_name(inst: &ast::ExplicitComponentInst) -> Option<String> {
    inst.component_insts
        .component_insts
        .first()
        .map(|ci| ci.id.clone())
}

fn extract_base_addr(insts: &ast::ComponentInsts) -> u32 {
    for ci in &insts.component_insts {
        if let Some(expr) = &ci.at {
            return eval_const_expr(expr) as u32;
        }
    }
    0
}

fn eval_const_expr(expr: &ast::ConstantExpr) -> u64 {
    match expr {
        ast::ConstantExpr::ConstantPrimary(primary, _) => eval_primary(primary),
        ast::ConstantExpr::UnaryOp(_, expr, _) => eval_const_expr(expr),
    }
}

fn eval_primary(primary: &ast::ConstantPrimary) -> u64 {
    match primary {
        ast::ConstantPrimary::Base(base) => eval_primary_base(base),
        ast::ConstantPrimary::Cast(base, _) => eval_primary_base(base),
    }
}

fn eval_primary_base(base: &ast::ConstantPrimaryBase) -> u64 {
    match base {
        ast::ConstantPrimaryBase::PrimaryLiteral(lit) => match lit {
            ast::PrimaryLiteral::Number(n) => *n,
            ast::PrimaryLiteral::BooleanLiteral(b) => *b as u64,
            _ => 0,
        },
        ast::ConstantPrimaryBase::ConstantExpr(expr) => eval_const_expr(expr),
        _ => 0,
    }
}

fn extract_desc_from_property(pa: &ast::PropertyAssignment) -> Option<String> {
    if let ast::PropertyAssignment::ExplicitOrDefaultPropAssignment(
        ast::ExplicitOrDefaultPropAssignment::ExplicitPropAssignment(
            _,
            ast::ExplicitPropertyAssignment::Assignment(
                ast::IdentityOrPropKeyword::Id(id),
                Some(ast::PropAssignmentRhs::ConstantExpr(expr)),
            ),
        ),
    ) = pa
    {
        if id == "desc" || id == "name" {
            if let ast::ConstantExpr::ConstantPrimary(
                ast::ConstantPrimary::Base(ast::ConstantPrimaryBase::PrimaryLiteral(
                    ast::PrimaryLiteral::StringLiteral(s),
                )),
                _,
            ) = expr
            {
                return Some(s.clone());
            }
        }
    }
    None
}

fn extract_sw_from_property(pa: &ast::PropertyAssignment) -> Option<FieldAccess> {
    if let ast::PropertyAssignment::ExplicitOrDefaultPropAssignment(
        ast::ExplicitOrDefaultPropAssignment::ExplicitPropAssignment(
            _,
            ast::ExplicitPropertyAssignment::Assignment(
                ast::IdentityOrPropKeyword::PropKeyword(ast::PropKeyword::Sw),
                Some(ast::PropAssignmentRhs::ConstantExpr(ast::ConstantExpr::ConstantPrimary(
                    ast::ConstantPrimary::Base(ast::ConstantPrimaryBase::PrimaryLiteral(
                        ast::PrimaryLiteral::AccessTypeLiteral(at),
                    )),
                    _,
                ))),
            ),
        ),
    ) = pa
    {
        return Some(match at {
            ast::AccessType::Rw => FieldAccess::RW,
            ast::AccessType::R => FieldAccess::RO,
            ast::AccessType::W => FieldAccess::WO,
            ast::AccessType::W1 => FieldAccess::W1C,
            _ => FieldAccess::RW,
        });
    }
    None
}

fn extract_onwrite_access(pa: &ast::PropertyAssignment) -> Option<FieldAccess> {
    if let ast::PropertyAssignment::ExplicitOrDefaultPropAssignment(
        ast::ExplicitOrDefaultPropAssignment::ExplicitPropAssignment(
            _,
            ast::ExplicitPropertyAssignment::Assignment(
                ast::IdentityOrPropKeyword::PropKeyword(ast::PropKeyword::WoClr),
                _,
            ),
        ),
    ) = pa
    {
        return Some(FieldAccess::W1C);
    }
    if let ast::PropertyAssignment::ExplicitOrDefaultPropAssignment(
        ast::ExplicitOrDefaultPropAssignment::ExplicitPropAssignment(
            _,
            ast::ExplicitPropertyAssignment::Assignment(
                ast::IdentityOrPropKeyword::PropKeyword(ast::PropKeyword::WoSet),
                _,
            ),
        ),
    ) = pa
    {
        return Some(FieldAccess::W1S);
    }
    None
}

/// Extract field access type from a post-property assignment (e.g., `FIELD_NAME->sw = r;`).
/// Returns `(field_name, access)` if matched.
fn extract_post_prop_sw(pa: &ast::PropertyAssignment) -> Option<(String, FieldAccess)> {
    if let ast::PropertyAssignment::PostPropAssignment(ast::PostPropAssignment::PropRef(
        prop_ref,
        rhs,
    )) = pa
    {
        let is_sw = matches!(
            &prop_ref.id_or_prop,
            ast::IdentityOrPropKeyword::PropKeyword(ast::PropKeyword::Sw)
        );
        if !is_sw {
            return None;
        }

        let field_name = prop_ref.iref.elements.first()?.id.clone();

        if let Some(ast::PropAssignmentRhs::ConstantExpr(ast::ConstantExpr::ConstantPrimary(
            ast::ConstantPrimary::Base(ast::ConstantPrimaryBase::PrimaryLiteral(
                ast::PrimaryLiteral::AccessTypeLiteral(at),
            )),
            _,
        ))) = rhs
        {
            let access = match at {
                ast::AccessType::Rw => FieldAccess::RW,
                ast::AccessType::R => FieldAccess::RO,
                ast::AccessType::W => FieldAccess::WO,
                ast::AccessType::W1 => FieldAccess::W1C,
                _ => FieldAccess::RW,
            };
            return Some((field_name, access));
        }
    }
    None
}

/// Extract field name from a post-property `woclr` assignment (e.g., `FIELD_NAME->woclr;`).
fn extract_post_prop_woclr(pa: &ast::PropertyAssignment) -> Option<String> {
    if let ast::PropertyAssignment::PostPropAssignment(ast::PostPropAssignment::PropRef(
        prop_ref,
        _,
    )) = pa
    {
        if matches!(
            &prop_ref.id_or_prop,
            ast::IdentityOrPropKeyword::PropKeyword(ast::PropKeyword::WoClr)
        ) {
            return Some(prop_ref.iref.elements.first()?.id.clone());
        }
    }
    None
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(ch.to_lowercase().next().unwrap());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_simple_rdl() {
        let rdl = r#"
            reg my_reg_t {
                field {} EN[0:0] = 0x0;
                field {} IE[1:1] = 0x0;
            };
            addrmap my_periph {
                my_reg_t CR @ 0x00;
            };
            addrmap soc {
                my_periph PERIPH @ 0x4000_0000;
            };
        "#;

        let root: ast::Root = rdl.parse().expect("parse failed");
        let schema = from_ast(&root, "test_soc").expect("translate failed");

        assert_eq!(schema.name, "test_soc");
        assert_eq!(schema.blocks.len(), 1);
        assert_eq!(schema.blocks[0].name, "my_periph");
        assert_eq!(schema.blocks[0].base_addr, 0x4000_0000);
        let regs: Vec<_> = schema.blocks[0].registers().collect();
        assert_eq!(regs.len(), 1);
        assert_eq!(regs[0].name, "CR");
        assert_eq!(regs[0].offset, 0);
        assert_eq!(regs[0].fields.len(), 2);
        assert_eq!(regs[0].fields[0].name, "EN");
        assert_eq!(regs[0].fields[1].name, "IE");
    }

    #[test]
    fn translate_post_prop_access_types() {
        let rdl = r#"
            reg sr_t {
                field {} FLAG[0:0] = 0x0;
                FLAG->sw = rw;
                FLAG->woclr;
            };
            reg cnt_t {
                field {} VAL[31:0] = 0x0;
                VAL->sw = r;
            };
            addrmap periph {
                sr_t SR @ 0x00;
                cnt_t CNT @ 0x04;
            };
            addrmap soc {
                periph P @ 0x4000_0000;
            };
        "#;

        let root: ast::Root = rdl.parse().expect("parse failed");
        let schema = from_ast(&root, "test").expect("translate failed");

        let regs: Vec<_> = schema.blocks[0].registers().collect();

        assert_eq!(regs[0].name, "SR");
        assert_eq!(regs[0].fields[0].access, FieldAccess::W1C);

        assert_eq!(regs[1].name, "CNT");
        assert_eq!(regs[1].fields[0].access, FieldAccess::RO);
    }
}
