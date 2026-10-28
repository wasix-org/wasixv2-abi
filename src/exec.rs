//! [`Model`] -> Rust source for `wasixv2-exec`: the import module name, `imports()` and one async
//! import shim per function. A shim decodes the wasm32 arguments, calls the `Syscalls` method,
//! then takes the return-to-guest path.

use std::fmt::Write as _;

use anyhow::{Result, bail};

use crate::ir::Model;
use crate::rust::{header, prim};
use crate::shape::{Method, Param, decode, decode_types, encode, methods, slice_type, uses_slice};

/// Items the generated module names, which ABI types must not shadow.
const LOCAL_ITEMS: &[&str] = &[
    "Arc",
    "AsyncFunctionEnvMut",
    "Caller",
    "Control",
    "ExecEnv",
    "Function",
    "FunctionEnv",
    "GuestMemory",
    "Imports",
    "Module",
    "RuntimeError",
    "Store",
    "Syscalls",
    "TaskId",
    "UserSlice",
    "UserSliceMut",
];

/// Generates the (unformatted) module for `model`.
pub fn generate(model: &Model, source: &str) -> Result<String> {
    let methods = methods(model)?;
    let types = decode_types(model, &methods);
    if let Some(t) = types.iter().find(|t| LOCAL_ITEMS.contains(&t.as_str())) {
        bail!("ABI type `{t}` collides with an item of wasixv2-exec");
    }
    let mut g = Gen {
        model,
        out: String::new(),
    };
    g.out.push_str(&header(source));
    g.prelude(&methods, &types);
    g.imports(&methods);
    for m in &methods {
        g.shim(m);
    }
    Ok(g.out)
}

struct Gen<'a> {
    model: &'a Model,
    out: String,
}

impl Gen<'_> {
    fn line(&mut self, s: &str) {
        self.out.push_str(s);
        self.out.push('\n');
    }

    fn prelude(&mut self, methods: &[Method], types: &std::collections::BTreeSet<String>) {
        self.line("");
        if !types.is_empty() {
            let types: Vec<&str> = types.iter().map(String::as_str).collect();
            let _ = writeln!(self.out, "use wasixv2_abi::{{{}}};", types.join(", "));
        }
        let mut items = vec!["Caller", "Control", "Syscalls"];
        items.extend(
            [false, true]
                .into_iter()
                .filter(|m| uses_slice(methods, *m))
                .map(slice_type),
        );
        let _ = writeln!(self.out, "use wasixv2_syscalls::{{{}}};", items.join(", "));
        self.line(
            "use wasmer::{AsyncFunctionEnvMut, Function, FunctionEnv, Imports, Module, RuntimeError, Store};",
        );
        self.line("");
        self.line("use crate::{ExecEnv, caller_parts, memory::GuestMemory, return_to_guest};");
        let module = methods.first().map_or("", |m| m.module);
        self.line("");
        self.line("/// Name of the import module that holds every syscall and extension.");
        let _ = writeln!(self.out, "pub const IMPORT_MODULE: &str = \"{module}\";");
    }

    fn imports(&mut self, methods: &[Method]) {
        self.line("");
        self.line(
            "/// The functions of [`IMPORT_MODULE`] that `module` imports, for an instance whose environment",
        );
        self.line(
            "/// is `env`. Only those: every instance (each thread, each image) defines its own. An import",
        );
        self.line("/// no syscall answers to stays undefined, and the module fails to link.");
        self.line(
            "pub(crate) fn imports<S>(store: &mut Store, env: &FunctionEnv<ExecEnv<S>>, module: &Module) -> Imports",
        );
        self.line("where S: Syscalls + Control + Send + Sync + 'static,");
        self.line("{");
        self.line("let mut imports = Imports::new();");
        self.line("for import in module.imports().functions() {");
        self.line("if import.module() != IMPORT_MODULE { continue; }");
        self.line("let function = match import.name() {");
        for m in methods {
            let _ = writeln!(
                self.out,
                "\"{}\" => Function::new_typed_with_env_async(store, env, {}::<S>),",
                m.f.import_name, m.name
            );
        }
        self.line("_ => continue,");
        self.line("};");
        self.line("imports.define(IMPORT_MODULE, import.name(), function);");
        self.line("}");
        self.line("imports");
        self.line("}");
    }

    fn shim(&mut self, m: &Method) {
        let mut params = vec!["env: AsyncFunctionEnvMut<ExecEnv<S>>".to_string()];
        params.extend(
            m.raw
                .iter()
                .map(|r| format!("{}: {}", r.name, prim(r.prim))),
        );
        let result = if m.ret.is_some() {
            prim(m.raw_ret)
        } else {
            "()"
        };
        self.line("");
        if params.len() > 7 {
            self.line("#[allow(clippy::too_many_arguments)]");
        }
        let _ = writeln!(
            self.out,
            "async fn {}<S>({}) -> Result<{result}, RuntimeError>",
            m.name,
            params.join(", ")
        );
        self.line("where S: Syscalls + Control + 'static,");
        self.line("{");
        self.line("let (syscalls, task) = caller_parts(&env).await;");
        self.line("let memory = GuestMemory { env: &env };");
        self.line("let caller = Caller::new(task, &memory);");
        // Qualified, since method syntax would find `Arc::clone` before `Syscalls::clone`.
        let mut args = vec!["&*syscalls".to_string(), "&caller".to_string()];
        args.extend(m.params.iter().map(|p| self.arg(m, p)));
        // The return-to-guest path answers `None` when a signal handler asks for the call to be
        // restarted (`SA_RESTART`), so the call runs again with the same arguments.
        self.line("loop {");
        let _ = writeln!(
            self.out,
            "let ret = Syscalls::{}({}).await;",
            m.name,
            args.join(", ")
        );
        match &m.ret {
            Some(t) => {
                let ret = match encode(self.model, t, "v", m.raw_ret) {
                    Some(expr) => format!("ret.map(|v| {expr})"),
                    None => "ret".to_string(),
                };
                let _ = writeln!(
                    self.out,
                    "if let Some(ret) = return_to_guest(&env, &*syscalls, task, {ret}).await {{ return ret; }}"
                );
            }
            None => {
                // TODO: a vfork child's `exit`, `exit_group` and successful `execve` resume the
                // parent, so the call returns to the guest; the return path needs a
                // `GuestAction` for that instead of this trap.
                self.line(
                    "if let Some(ret) = return_to_guest(&env, &*syscalls, task, ret.map(|()| 0)).await {",
                );
                self.line("ret?;");
                let _ = writeln!(
                    self.out,
                    "return Err(RuntimeError::new(\"`{}` returned to the guest\"));",
                    m.f.import_name
                );
                self.line("}");
            }
        }
        self.line("}");
        self.line("}");
    }

    fn arg(&self, m: &Method, p: &Param) -> String {
        match p {
            Param::Value { raw, .. } => decode(self.model, &m.raw[*raw]),
            Param::Slice {
                mutable, ptr, len, ..
            } => format!(
                "{}::new({} as u32, {} as u32)",
                slice_type(*mutable),
                m.raw[*ptr].name,
                m.raw[*len].name
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::tests::model;

    #[test]
    fn shims_decode_and_encode() {
        let out = generate(
            &model(
                "/// @slice(buf, count)\n/// @returns(u32)\nread: func(fd: fd, buf: buf, count: usize) -> slong;\n\
                 /// @returns(fd)\nopenat: func(dfd: fd, path: cstr, mode: u32, pos: s64) -> slong;\n\
                 /// @noreturn\nexit-group: func(error-code: s32);\ngetpid: func() -> slong;\n\
                 lseek: func(fd: fd, offset: s64, whence: u32) -> s64;",
            ),
            "t.wit",
        )
        .unwrap();
        for want in [
            "pub const IMPORT_MODULE: &str = \"m\";",
            "pub(crate) fn imports<S>(store: &mut Store, env: &FunctionEnv<ExecEnv<S>>, module: &Module) -> Imports",
            "if import.module() != IMPORT_MODULE { continue; }",
            "\"exit_group\" => Function::new_typed_with_env_async(store, env, exit_group::<S>),",
            "_ => continue,",
            "imports.define(IMPORT_MODULE, import.name(), function);",
            "async fn read<S>(env: AsyncFunctionEnvMut<ExecEnv<S>>, fd: i32, buf: i32, count: i32) -> Result<i32, RuntimeError>",
            "let ret = Syscalls::read(&*syscalls, &caller, Fd(fd), UserSliceMut::new(buf as u32, count as u32)).await;",
            "if let Some(ret) = return_to_guest(&env, &*syscalls, task, ret.map(|v| v as i32)).await { return ret; }",
            "let ret = Syscalls::openat(&*syscalls, &caller, Fd(dfd), Cstr::new(path as u32), mode as u32, pos).await;",
            "if let Some(ret) = return_to_guest(&env, &*syscalls, task, ret.map(|v| v.0)).await { return ret; }",
            "async fn exit_group<S>(env: AsyncFunctionEnvMut<ExecEnv<S>>, error_code: i32) -> Result<(), RuntimeError>",
            "return Err(RuntimeError::new(\"`exit_group` returned to the guest\"));",
            "if let Some(ret) = return_to_guest(&env, &*syscalls, task, ret).await { return ret; }\n",
            "async fn lseek<S>(env: AsyncFunctionEnvMut<ExecEnv<S>>, fd: i32, offset: i64, whence: i32) -> Result<i64, RuntimeError>",
            "use wasixv2_abi::{Cstr, Fd};",
            "use wasixv2_syscalls::{Caller, Control, Syscalls, UserSliceMut};",
            "use crate::{ExecEnv, caller_parts, memory::GuestMemory, return_to_guest};",
            "use wasmer::{AsyncFunctionEnvMut, Function, FunctionEnv, Imports, Module, RuntimeError, Store};",
        ] {
            assert!(out.contains(want), "missing `{want}` in:\n{out}");
        }
    }
}
