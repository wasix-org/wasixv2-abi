//! [`Model`] -> Rust source for `wasixv2-syscalls`: the `Syscalls` trait with one async method
//! per import, the `Syscall` request enum, `SyscallRet`, `dispatch`, the `Layer` trait and the
//! forwarding `Layered` adapter.

use std::fmt::Write as _;

use anyhow::{Result, bail};

use crate::ir::{Model, Prim, SplitOrder, TyRef};
use crate::rust::{cast, header, push_docs, ty};
use crate::shape::{Method, Param, Repr, methods, repr, signature_types, slice_type, uses_slice};

/// Items of `wasixv2-syscalls` the generated module names, which ABI types must not shadow.
const LOCAL_ITEMS: &[&str] = &[
    "Caller",
    "Control",
    "Layer",
    "Layered",
    "SysResult",
    "Syscall",
    "SyscallRet",
    "Syscalls",
    "TaskId",
    "UserSlice",
    "UserSliceMut",
];

/// Generates the (unformatted) module for `model`.
pub fn generate(model: &Model, source: &str) -> Result<String> {
    let methods = methods(model)?;
    let mut types = signature_types(&methods);
    if let Some(t) = types.iter().find(|t| LOCAL_ITEMS.contains(&t.as_str())) {
        bail!("ABI type `{t}` collides with an item of wasixv2-syscalls");
    }
    types.insert("Errno".to_string());
    let mut g = Gen { out: String::new() };
    g.out.push_str(&header(source));
    g.imports(&methods, &types);
    g.trait_def(&methods);
    g.enums(model, &methods);
    g.registers(model, &methods);
    g.dispatch(&methods);
    g.out.push_str(LAYER);
    g.layered(&methods);
    Ok(g.out)
}

struct Gen {
    out: String,
}

impl Gen {
    fn line(&mut self, s: &str) {
        self.out.push_str(s);
        self.out.push('\n');
    }

    fn imports(&mut self, methods: &[Method], types: &std::collections::BTreeSet<String>) {
        let types: Vec<&str> = types.iter().map(String::as_str).collect();
        let _ = writeln!(self.out, "\nuse wasixv2_abi::{{{}}};\n", types.join(", "));
        let slices: Vec<&str> = [false, true]
            .into_iter()
            .filter(|m| uses_slice(methods, *m))
            .map(slice_type)
            .collect();
        let memory = match slices.as_slice() {
            [] => String::new(),
            [one] => format!("memory::{one}, "),
            many => format!("memory::{{{}}}, ", many.join(", ")),
        };
        let _ = writeln!(
            self.out,
            "use crate::{{caller::Caller, {memory}result::SysResult}};"
        );
    }

    fn trait_def(&mut self, methods: &[Method]) {
        self.out.push_str(TRAIT_DOCS);
        self.line("pub trait Syscalls {");
        for m in methods {
            self.line("");
            push_docs(&mut self.out, &m.f.docs);
            if !m.f.docs.is_empty() {
                self.line("///");
            }
            self.line(&m.import_doc());
            if m.f.unsupported {
                self.line("///");
                self.line(
                    "/// Declared for completeness; implementations may leave it unimplemented.",
                );
            }
            if m.too_many_args() {
                self.line("#[allow(clippy::too_many_arguments)]");
            }
            let _ = writeln!(self.out, "{} {{ Err(Errno::ENOSYS.into()) }}", signature(m));
        }
        self.line("}");
    }

    fn enums(&mut self, model: &Model, methods: &[Method]) {
        self.line("");
        self.line("/// One syscall with its arguments, for layers that treat every call alike.");
        self.line("#[derive(Clone, Copy, Debug, PartialEq, Eq)]");
        self.line("pub enum Syscall {");
        for m in methods {
            let params = m.typed_params();
            if params.is_empty() {
                let _ = writeln!(self.out, "{},", m.variant);
            } else {
                let _ = writeln!(self.out, "{} {{ {} }},", m.variant, params.join(", "));
            }
        }
        self.line("}");
        self.line("");
        self.line("/// The value a [`Syscall`] produced.");
        self.line("#[derive(Clone, Copy, Debug, PartialEq, Eq)]");
        self.line("pub enum SyscallRet {");
        for m in methods {
            match m.ret_type() {
                Some(t) => {
                    let _ = writeln!(self.out, "{}({t}),", m.variant);
                }
                None => {
                    let _ = writeln!(self.out, "{},", m.variant);
                }
            }
        }
        self.line("}");
        self.line("");
        self.line("impl SyscallRet {");
        self.line(
            "/// The raw result the guest sees, as riscv32's `a0` holds it and a tracer reads it",
        );
        self.line("/// (`syscall_get_return_value`): a 32-bit `long`, sign-extended; 64-bit values whole.");
        self.line(
            "/// The inverse of [`Syscall::ret_from_raw`]; a call without a value returns 0.",
        );
        self.line("pub fn to_raw(&self) -> i64 {");
        self.line("match *self {");
        for m in methods {
            let value = match &m.ret {
                Some(t) => format!("SyscallRet::{}(v) => {}", m.variant, encode_raw(model, t)),
                None => format!("SyscallRet::{} => 0", m.variant),
            };
            let _ = writeln!(self.out, "{value},");
        }
        self.line("}");
        self.line("}");
        self.line("}");
    }

    /// `impl Syscall`: the call as riscv32 makes it, for filters and tracers that see the raw
    /// registers (`seccomp_data`, `ptrace`), and the typed result of a raw return value.
    fn registers(&mut self, model: &Model, methods: &[Method]) {
        self.line("");
        self.line("impl Syscall {");
        self.line("/// The riscv32 syscall number, as `seccomp_data.nr` and `PTRACE_GET_SYSCALL_INFO` see it;");
        self.line("/// `None` for the wasm-specific extensions, which have none.");
        self.line("pub fn nr(&self) -> Option<u32> {");
        self.line("match self {");
        for m in methods {
            let nr = m.f.nr.map_or("None".to_string(), |n| format!("Some({n})"));
            let _ = writeln!(self.out, "{} => {nr},", wildcard(m));
        }
        self.line("}");
        self.line("}");
        self.line("");
        self.line(
            "/// The arguments as riscv32 passes them in `a0` to `a5`, each zero-extended from its",
        );
        self.line("/// 32-bit register as `seccomp_data.args` holds them: a 64-bit argument riscv32 splits");
        self.line("/// (`@merged-i64`) takes two registers, a pointer and length pair two, and an extension's");
        self.line("/// arguments past the sixth are left out.");
        self.line("pub fn args(&self) -> [u64; 6] {");
        self.line("match *self {");
        for m in methods {
            let regs = registers(model, m);
            let _ = writeln!(self.out, "{} => regs([{}]),", pattern(m), regs.join(", "));
        }
        self.line("}");
        self.line("}");
        self.line("");
        self.line("/// What this call returns when its raw result (the value or `-errno` the guest sees) is");
        self.line("/// `raw`, for a layer that answers a call without running it.");
        self.line("pub fn ret_from_raw(&self, raw: i64) -> SyscallRet {");
        self.line("match self {");
        for m in methods {
            let value = match &m.ret {
                Some(t) => format!("SyscallRet::{}({})", m.variant, decode_raw(model, t)),
                None => format!("SyscallRet::{}", m.variant),
            };
            let _ = writeln!(self.out, "{} => {value},", wildcard(m));
        }
        self.line("}");
        self.line("}");
        self.line("}");
        self.line("");
        self.line("/// `r` padded with zeroes, or cut, to six registers.");
        self.line("fn regs<const N: usize>(r: [u64; N]) -> [u64; 6] {");
        self.line("let mut out = [0; 6];");
        self.line("for (o, r) in out.iter_mut().zip(r) { *o = r; }");
        self.line("out");
        self.line("}");
    }

    fn dispatch(&mut self, methods: &[Method]) {
        self.line("");
        self.line("pub async fn dispatch<S: Syscalls + ?Sized>(");
        self.line("syscalls: &S, caller: &Caller<'_>, call: Syscall,");
        self.line(") -> SysResult<SyscallRet> {");
        self.line("Ok(match call {");
        for m in methods {
            let call = format!("syscalls.{}({}).await?", m.name, call_args(m).join(", "));
            let pattern = pattern(m);
            match m.ret {
                Some(_) => {
                    let _ = writeln!(self.out, "{pattern} => SyscallRet::{}({call}),", m.variant);
                }
                None => {
                    let _ = writeln!(
                        self.out,
                        "{pattern} => {{ {call}; SyscallRet::{} }}",
                        m.variant
                    );
                }
            }
        }
        self.line("})");
        self.line("}");
    }

    fn layered(&mut self, methods: &[Method]) {
        self.line("");
        self.line("impl<L: Layer<S>, S: Syscalls> Syscalls for Layered<L, S> {");
        for m in methods {
            self.line("");
            if m.too_many_args() {
                self.line("#[allow(clippy::too_many_arguments)]");
            }
            let _ = writeln!(self.out, "{} {{", signature(m));
            let _ = writeln!(self.out, "let call = {};", pattern(m));
            self.line("match self.layer.call(caller, call, &self.inner).await? {");
            match m.ret {
                Some(_) => {
                    let _ = writeln!(self.out, "SyscallRet::{}(ret) => Ok(ret),", m.variant);
                }
                None => {
                    let _ = writeln!(self.out, "SyscallRet::{} => Ok(()),", m.variant);
                }
            }
            let _ = writeln!(self.out, "_ => mismatch(\"{}\"),", m.f.import_name);
            self.line("}");
            self.line("}");
        }
        self.line("}");
        self.out.push_str(CONTROL);
    }
}

/// `async fn name(&self, caller: &Caller<'_>, ...) -> SysResult<T>`.
fn signature(m: &Method) -> String {
    let mut params = vec!["&self".to_string(), "caller: &Caller<'_>".to_string()];
    params.extend(m.typed_params());
    format!(
        "async fn {}({}) -> {}",
        m.name,
        params.join(", "),
        m.result_type()
    )
}

fn call_args(m: &Method) -> Vec<String> {
    let mut args = vec!["caller".to_string()];
    args.extend(m.param_names().into_iter().map(str::to_string));
    args
}

/// `Syscall::Name { .. }`, or `Syscall::Name` for a call without params.
fn wildcard(m: &Method) -> String {
    match m.params.is_empty() {
        true => format!("Syscall::{}", m.variant),
        false => format!("Syscall::{} {{ .. }}", m.variant),
    }
}

/// The register values of `m`'s raw params, in import order, from the typed params bound by
/// [`pattern`].
fn registers(model: &Model, m: &Method) -> Vec<String> {
    let mut out = Vec::new();
    for (i, r) in m.raw.iter().enumerate() {
        let slice = m.params.iter().find_map(|p| match p {
            Param::Slice { name, ptr, .. } if *ptr == i => Some(format!("{name}.addr")),
            Param::Slice { name, len, .. } if *len == i => Some(format!("{name}.len")),
            _ => None,
        });
        if let Some(field) = slice {
            out.push(format!("u64::from({field})"));
            continue;
        }
        let name = m.params.iter().find_map(|p| match p {
            Param::Value { name, raw, .. } if *raw == i => Some(name.as_str()),
            _ => None,
        });
        let name = name.expect("every raw param is a value or part of a slice");
        let (value, p) = match repr(model, &r.ty) {
            Repr::Int(p) => (name.to_string(), p),
            Repr::Ptr => (format!("{name}.addr()"), Prim::U32),
            Repr::Wrapped { prim, .. } => (format!("{name}.0"), prim),
        };
        let wit = &m.f.params[i].name;
        match p {
            Prim::U64 | Prim::S64 if m.f.merged_i64.iter().any(|x| &x.param == wit) => {
                let v = cast(&value, p, Prim::U64);
                let (lo, hi) = (format!("({v}) & 0xffff_ffff"), format!("({v}) >> 32"));
                match m.f.split_order(wit) {
                    SplitOrder::LoHi => out.extend([lo, hi]),
                    SplitOrder::HiLo => out.extend([hi, lo]),
                }
            }
            Prim::U64 | Prim::S64 => out.push(cast(&value, p, Prim::U64)),
            Prim::U32 => out.push(format!("u64::from({value})")),
            _ => out.push(format!("u64::from({})", cast(&value, p, Prim::U32))),
        }
    }
    out
}

/// The typed success value `t` of a raw result `raw` (an `i64`).
fn decode_raw(model: &Model, t: &TyRef) -> String {
    match repr(model, t) {
        Repr::Int(p) => cast("raw", Prim::S64, p),
        Repr::Ptr => format!("{}::new(raw as u32)", ty(t)),
        Repr::Wrapped { ctor, prim } => format!("{ctor}({})", cast("raw", Prim::S64, prim)),
    }
}

/// `v`, the value of a result of type `t`, as the raw `i64` a register holds (see
/// [`decode_raw`]): 32-bit values sign-extended as a `long`, 64-bit ones whole.
fn encode_raw(model: &Model, t: &TyRef) -> String {
    let widen = |expr: &str, p: Prim| match p.size() {
        8 => cast(expr, p, Prim::S64),
        _ => format!("{} as i64", cast(expr, p, Prim::S32)),
    };
    match repr(model, t) {
        Repr::Int(p) => widen("v", p),
        Repr::Ptr => "v.addr() as i32 as i64".to_string(),
        Repr::Wrapped { prim, .. } => widen("v.0", prim),
    }
}

/// `Syscall::Name { a, b }`, also usable as an expression.
fn pattern(m: &Method) -> String {
    let names = m.param_names();
    if names.is_empty() {
        format!("Syscall::{}", m.variant)
    } else {
        format!("Syscall::{} {{ {} }}", m.variant, names.join(", "))
    }
}

const TRAIT_DOCS: &str = r#"
/// One async method per import of the guest ABI, with typed arguments.
///
/// Every method fails with `ENOSYS` unless overridden, so an implementation (the kernel, a test
/// double) provides only the syscalls it supports.
// The futures are deliberately not `Send`: wasmer's async host calls are not.
#[allow(async_fn_in_trait, unused_variables)]
"#;

const LAYER: &str = r#"
/// A layer that sees every syscall as a [`Syscall`] value.
///
/// A layer is written for the syscalls `S` it runs in front of: a generic one (a tracer) for
/// every `S`, one that needs more of what it wraps (the kernel's syscall entry) for that type.
#[allow(async_fn_in_trait)]
pub trait Layer<S: Syscalls> {
    async fn call(
        &self,
        caller: &Caller<'_>,
        call: Syscall,
        next: &S,
    ) -> SysResult<SyscallRet>;
}

/// Runs `layer` in front of `inner`.
pub struct Layered<L, S> {
    pub layer: L,
    pub inner: S,
}

impl<L, S> Layered<L, S> {
    pub fn new(layer: L, inner: S) -> Self {
        Self { layer, inner }
    }
}

fn mismatch(call: &str) -> ! {
    unreachable!("a layer answered `{call}` with another syscall's result")
}
"#;

const CONTROL: &str = r#"
impl<L, S: crate::Control> crate::Control for Layered<L, S> {
    fn take_pending(&self, task: crate::TaskId) -> Option<crate::GuestAction> {
        self.inner.take_pending(task)
    }

    fn run_task_work<'a>(&'a self, caller: &'a crate::Caller<'_>) -> crate::LocalFuture<'a, ()> {
        self.inner.run_task_work(caller)
    }

    fn signal_return(&self, task: crate::TaskId, mask: Option<u64>) {
        self.inner.signal_return(task, mask)
    }

    fn take_image(&self, task: crate::TaskId) -> Option<crate::Image> {
        self.inner.take_image(task)
    }

    fn work_flag(&self, task: crate::TaskId) -> std::sync::Arc<crate::WorkFlag> {
        self.inner.work_flag(task)
    }

    fn exec_wait(&self, task: crate::TaskId) -> crate::LocalFuture<'_, Result<(), i32>> {
        self.inner.exec_wait(task)
    }

    fn group_wait(&self, task: crate::TaskId) -> crate::LocalFuture<'_, ()> {
        self.inner.group_wait(task)
    }

    fn fault(&self, task: crate::TaskId, signal: i32) -> bool {
        self.inner.fault(task, signal)
    }

    fn release(&self, task: crate::TaskId) {
        self.inner.release(task)
    }

    fn abort_thread(&self, task: crate::TaskId) {
        self.inner.abort_thread(task)
    }
}
"#;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ir::Target;
    use crate::parse::parse_str;

    pub(crate) const TYPES: &str = "package t:t@0.1.0;\ninterface types {\n/// @pointer-sized\ntype uptr = u32;\n/// @pointer-sized\ntype slong = s32;\n/// @pointer-sized\ntype usize = u32;\n/// @newtype\ntype fd = s32;\n/// @ptr(mut u8[])\ntype buf = uptr;\n/// @ptr(const u8[])\ntype cstr = uptr;\n/// @repr(s32)\n/// @abi-error\nenum errno {\n/// @value(38)\nenosys }\n}\n";

    pub(crate) fn model(funcs: &str) -> Model {
        let src = format!(
            "{TYPES}/// @module(m)\ninterface s {{\nuse types.{{uptr, slong, usize, fd, buf, cstr}};\n{funcs}\n}}\n"
        );
        parse_str("t.wit", &src, Target::WASM32).unwrap()
    }

    #[test]
    fn slices_and_returns_shape_the_signature() {
        let out = generate(
            &model(
                "/// @nr(63)\n/// @slice(buf, count)\n/// @returns(u32)\nread: func(fd: fd, buf: buf, count: usize) -> slong;\n\
                 /// @returns(fd)\nopenat: func(dfd: fd, path: cstr) -> slong;\n\
                 /// @noreturn\nexit-group: func(error-code: s32);\ngetpid: func() -> slong;",
            ),
            "t.wit",
        )
        .unwrap();
        for want in [
            "async fn read(&self, caller: &Caller<'_>, fd: Fd, buf: UserSliceMut) -> SysResult<u32> { Err(Errno::ENOSYS.into()) }",
            "async fn openat(&self, caller: &Caller<'_>, dfd: Fd, path: Cstr) -> SysResult<Fd>",
            "async fn exit_group(&self, caller: &Caller<'_>, error_code: i32) -> SysResult<()>",
            "async fn getpid(&self, caller: &Caller<'_>) -> SysResult<i32>",
            "Read { fd: Fd, buf: UserSliceMut },",
            "Getpid,\n",
            "ExitGroup,\n",
            "Read(u32),",
            "Syscall::ExitGroup { error_code } => { syscalls.exit_group(caller, error_code).await?; SyscallRet::ExitGroup }",
            "Syscall::Getpid => SyscallRet::Getpid(syscalls.getpid(caller).await?),",
            "SyscallRet::Openat(ret) => Ok(ret),",
            "_ => mismatch(\"exit_group\"),",
            "/// Wasm import `m.read` (riscv32 nr 63).",
            "use wasixv2_abi::{Cstr, Errno, Fd};",
            "use crate::{caller::Caller, memory::UserSliceMut, result::SysResult};",
            "fn take_image(&self, task: crate::TaskId) -> Option<crate::Image> {",
        ] {
            assert!(out.contains(want), "missing `{want}` in:\n{out}");
        }
    }

    #[test]
    fn calls_know_their_registers() {
        let out = generate(
            &model(
                "/// @nr(63)\n/// @slice(buf, count)\n/// @returns(u32)\nread: func(fd: fd, buf: buf, count: usize) -> slong;\n\
                 /// @nr(67)\n/// @merged-i64(pos)\npread: func(fd: fd, buf: uptr, pos: s64) -> slong;\n\
                 /// @nr(62)\n/// @merged-i64(pos, hi-lo)\nllseek: func(pos: s64) -> slong;\n\
                 /// @returns(fd)\nopenat: func(dfd: fd, path: cstr) -> slong;\n\
                 /// @noreturn\nexit-group: func(error-code: s32);",
            ),
            "t.wit",
        )
        .unwrap();
        for want in [
            "Syscall::Read { .. } => Some(63),",
            "Syscall::Openat { .. } => None,",
            "Syscall::Read { fd, buf } => regs([u64::from(fd.0 as u32), u64::from(buf.addr), u64::from(buf.len)]),",
            "Syscall::Pread { fd, buf, pos } => regs([u64::from(fd.0 as u32), u64::from(buf), (pos as u64) & 0xffff_ffff, (pos as u64) >> 32]),",
            "Syscall::Llseek { pos } => regs([(pos as u64) >> 32, (pos as u64) & 0xffff_ffff]),",
            "Syscall::Openat { dfd, path } => regs([u64::from(dfd.0 as u32), u64::from(path.addr())]),",
            "Syscall::Read { .. } => SyscallRet::Read(raw as u32),",
            "Syscall::Openat { .. } => SyscallRet::Openat(Fd(raw as i32)),",
            "Syscall::ExitGroup { .. } => SyscallRet::ExitGroup,",
            "pub trait Layer<S: Syscalls> {",
            "impl<L: Layer<S>, S: Syscalls> Syscalls for Layered<L, S> {",
        ] {
            assert!(out.contains(want), "missing `{want}` in:\n{out}");
        }
    }

    #[test]
    fn rejects_unusable_shapes() {
        let e = |funcs: &str| format!("{:#}", generate(&model(funcs), "t.wit").unwrap_err());
        assert!(e("x: func(a-b: s32, A-B: s32) -> slong;").contains("duplicate `a_b`"));
        assert!(e("x: func();").contains("is not `@noreturn`"));
        assert!(e("imports: func() -> slong;").contains("reserved by generated code"));
        assert!(e("module: func() -> slong;").contains("reserved by generated code"));
        let e = e("x-y: func() -> slong;\n/// @import(z)\nX-Y: func() -> slong;");
        assert!(e.contains("both map to Rust method `x_y`"), "{e}");
    }

    #[test]
    fn one_import_module() {
        let src = format!(
            "{TYPES}/// @module(a)\ninterface a {{\nx: func() -> s32;\n}}\n/// @module(b)\ninterface b {{\ny: func() -> s32;\n}}\n"
        );
        let m = parse_str("t.wit", &src, Target::WASM32).unwrap();
        let e = format!("{:#}", generate(&m, "t.wit").unwrap_err());
        assert!(e.contains("imported from both `a` and `b`"), "{e}");
    }
}
