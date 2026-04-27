"""
AST 引擎 - PHP 漏洞扫描核心逻辑
后端主分析：基于 PHP AST（phply）做 Source/Sink 与污点传播分析，
并保留 WebShell 特征匹配与解析失败回退能力。
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


try:
    from phply.phplex import lexer as php_lexer
    from phply.phpparse import make_parser

    PHP_AST_AVAILABLE = True
except Exception:
    php_lexer = None
    make_parser = None
    PHP_AST_AVAILABLE = False


class VulnerabilityType(str, Enum):
    SQL_INJECTION = "SQL 注入"
    XSS = "跨站脚本攻击 (XSS)"
    CODE_EXECUTION = "远程代码执行 (RCE)"
    FILE_INCLUSION = "文件包含 (LFI/RFI)"
    SENSITIVE_CALL = "敏感函数调用"
    SSRF = "服务端请求伪造 (SSRF)"
    DESERIALIZATION = "不安全的反序列化"
    PATH_TRAVERSAL = "路径穿越/任意文件操作"
    FILE_UPLOAD = "不安全的文件上传"
    WEAK_CRYPTO = "弱加密/哈希算法"
    HEADER_INJECTION = "HTTP 头部注入"
    LDAP_INJECTION = "LDAP 注入"
    WEBSHELL = "Webshell 恶意后门"
    CUSTOM = "自定义规则"


class RiskLevel(str, Enum):
    CRITICAL = "严重"
    HIGH = "高危"
    MEDIUM = "中危"
    LOW = "低危"
    INFO = "提示"


@dataclass
class Rule:
    id: str
    name: str
    pattern: str
    type: VulnerabilityType
    level: RiskLevel
    enabled: bool = True
    is_built_in: bool = True
    description: Optional[str] = None


@dataclass
class Vulnerability:
    id: str
    type: VulnerabilityType
    level: RiskLevel
    line: int
    file_name: str
    snippet: str
    description: str
    source: str = ""
    sink: str = ""


@dataclass
class SinkSpec:
    vuln_type: VulnerabilityType
    level: RiskLevel
    require_taint: bool = True


class ASTEngine:
    """后端主分析引擎（AST 驱动）"""

    SOURCE_SUPERGLOBALS = {
        "_GET",
        "_POST",
        "_REQUEST",
        "_COOKIE",
        "_SERVER",
        "_FILES",
        "_SESSION",
        "_ENV",
    }

    SANITIZERS = {
        "intval",
        "floatval",
        "abs",
        "htmlspecialchars",
        "htmlentities",
        "strip_tags",
        "urlencode",
        "rawurlencode",
        "mysqli_real_escape_string",
        "pg_escape_string",
        "addslashes",
        "escapeshellarg",
        "escapeshellcmd",
        "filter_input",
        "filter_var",
        "ctype_digit",
        "is_numeric",
        "basename",
        "realpath",
        "pathinfo",
        "password_hash",
    }

    DYNAMIC_SOURCES = {
        "getenv",
        "getallheaders",
        "apache_request_headers",
    }

    SINKS: Dict[str, SinkSpec] = {
        "mysql_query": SinkSpec(VulnerabilityType.SQL_INJECTION, RiskLevel.CRITICAL, True),
        "mysqli_query": SinkSpec(VulnerabilityType.SQL_INJECTION, RiskLevel.CRITICAL, True),
        "pg_query": SinkSpec(VulnerabilityType.SQL_INJECTION, RiskLevel.CRITICAL, True),
        "query": SinkSpec(VulnerabilityType.SQL_INJECTION, RiskLevel.CRITICAL, True),
        "execute": SinkSpec(VulnerabilityType.SQL_INJECTION, RiskLevel.CRITICAL, True),
        "eval": SinkSpec(VulnerabilityType.CODE_EXECUTION, RiskLevel.CRITICAL, True),
        "assert": SinkSpec(VulnerabilityType.CODE_EXECUTION, RiskLevel.CRITICAL, True),
        "system": SinkSpec(VulnerabilityType.CODE_EXECUTION, RiskLevel.CRITICAL, True),
        "exec": SinkSpec(VulnerabilityType.CODE_EXECUTION, RiskLevel.CRITICAL, True),
        "passthru": SinkSpec(VulnerabilityType.CODE_EXECUTION, RiskLevel.CRITICAL, True),
        "shell_exec": SinkSpec(VulnerabilityType.CODE_EXECUTION, RiskLevel.CRITICAL, True),
        "popen": SinkSpec(VulnerabilityType.CODE_EXECUTION, RiskLevel.CRITICAL, True),
        "proc_open": SinkSpec(VulnerabilityType.CODE_EXECUTION, RiskLevel.CRITICAL, True),
        "include": SinkSpec(VulnerabilityType.FILE_INCLUSION, RiskLevel.HIGH, True),
        "include_once": SinkSpec(VulnerabilityType.FILE_INCLUSION, RiskLevel.HIGH, True),
        "require": SinkSpec(VulnerabilityType.FILE_INCLUSION, RiskLevel.HIGH, True),
        "require_once": SinkSpec(VulnerabilityType.FILE_INCLUSION, RiskLevel.HIGH, True),
        "file_get_contents": SinkSpec(VulnerabilityType.FILE_INCLUSION, RiskLevel.HIGH, True),
        "readfile": SinkSpec(VulnerabilityType.FILE_INCLUSION, RiskLevel.HIGH, True),
        "fopen": SinkSpec(VulnerabilityType.FILE_INCLUSION, RiskLevel.HIGH, True),
        "move_uploaded_file": SinkSpec(VulnerabilityType.FILE_UPLOAD, RiskLevel.CRITICAL, True),
        "file_put_contents": SinkSpec(VulnerabilityType.FILE_UPLOAD, RiskLevel.CRITICAL, True),
        "fwrite": SinkSpec(VulnerabilityType.FILE_UPLOAD, RiskLevel.CRITICAL, True),
        "copy": SinkSpec(VulnerabilityType.FILE_UPLOAD, RiskLevel.CRITICAL, True),
        "unlink": SinkSpec(VulnerabilityType.PATH_TRAVERSAL, RiskLevel.HIGH, True),
        "rename": SinkSpec(VulnerabilityType.PATH_TRAVERSAL, RiskLevel.HIGH, True),
        "mkdir": SinkSpec(VulnerabilityType.PATH_TRAVERSAL, RiskLevel.HIGH, True),
        "rmdir": SinkSpec(VulnerabilityType.PATH_TRAVERSAL, RiskLevel.HIGH, True),
        "chmod": SinkSpec(VulnerabilityType.PATH_TRAVERSAL, RiskLevel.HIGH, True),
        "curl_init": SinkSpec(VulnerabilityType.SSRF, RiskLevel.HIGH, True),
        "fsockopen": SinkSpec(VulnerabilityType.SSRF, RiskLevel.HIGH, True),
        "pfsockopen": SinkSpec(VulnerabilityType.SSRF, RiskLevel.HIGH, True),
        "get_headers": SinkSpec(VulnerabilityType.SSRF, RiskLevel.HIGH, True),
        "unserialize": SinkSpec(VulnerabilityType.DESERIALIZATION, RiskLevel.CRITICAL, True),
        "yaml_parse": SinkSpec(VulnerabilityType.DESERIALIZATION, RiskLevel.CRITICAL, True),
        "json_decode": SinkSpec(VulnerabilityType.DESERIALIZATION, RiskLevel.MEDIUM, True),
        "phpinfo": SinkSpec(VulnerabilityType.SENSITIVE_CALL, RiskLevel.INFO, False),
        "var_dump": SinkSpec(VulnerabilityType.SENSITIVE_CALL, RiskLevel.INFO, False),
        "debug_backtrace": SinkSpec(VulnerabilityType.SENSITIVE_CALL, RiskLevel.INFO, False),
        "print_r": SinkSpec(VulnerabilityType.SENSITIVE_CALL, RiskLevel.INFO, False),
        "rand": SinkSpec(VulnerabilityType.WEAK_CRYPTO, RiskLevel.MEDIUM, False),
        "mt_rand": SinkSpec(VulnerabilityType.WEAK_CRYPTO, RiskLevel.MEDIUM, False),
        "uniqid": SinkSpec(VulnerabilityType.WEAK_CRYPTO, RiskLevel.MEDIUM, False),
        "md5": SinkSpec(VulnerabilityType.WEAK_CRYPTO, RiskLevel.LOW, False),
        "sha1": SinkSpec(VulnerabilityType.WEAK_CRYPTO, RiskLevel.LOW, False),
        "header": SinkSpec(VulnerabilityType.HEADER_INJECTION, RiskLevel.MEDIUM, True),
        "setcookie": SinkSpec(VulnerabilityType.HEADER_INJECTION, RiskLevel.MEDIUM, True),
        "ldap_search": SinkSpec(VulnerabilityType.LDAP_INJECTION, RiskLevel.MEDIUM, True),
        "ldap_list": SinkSpec(VulnerabilityType.LDAP_INJECTION, RiskLevel.MEDIUM, True),
        "ldap_read": SinkSpec(VulnerabilityType.LDAP_INJECTION, RiskLevel.MEDIUM, True),
        # XSS sinks
        "echo": SinkSpec(VulnerabilityType.XSS, RiskLevel.HIGH, True),
        "print": SinkSpec(VulnerabilityType.XSS, RiskLevel.HIGH, True),
        # Laravel
        "db::raw": SinkSpec(VulnerabilityType.SQL_INJECTION, RiskLevel.CRITICAL, True),
        # Reflection / dynamic invocation
        "invoke": SinkSpec(VulnerabilityType.CODE_EXECUTION, RiskLevel.CRITICAL, True),
    }

    WEBSHELL_REGEX_RULES: List[Rule] = [
        Rule(
            id="w1",
            name="一句话木马特征 (Eval/Assert)",
            pattern=r"(eval|assert|preg_replace\s*?\(\s*?[\'\"].*?\/e[\'\"])\s*?\(\s*?(\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)|base64_decode|gzinflate|str_rot13)",
            type=VulnerabilityType.WEBSHELL,
            level=RiskLevel.CRITICAL,
        ),
        Rule(
            id="w2",
            name="动态函数调用 (变量执行)",
            pattern=r"\$(\w+)\s*?\(\s*?\$_(POST|GET|REQUEST|COOKIE)",
            type=VulnerabilityType.WEBSHELL,
            level=RiskLevel.CRITICAL,
        ),
        Rule(
            id="w3",
            name="代码隐写/混淆加载",
            pattern=r"(base64_decode|gzinflate|str_rot13|hex2bin|pack|unpack)\s*?\(.*?(\$_(POST|GET|REQUEST|COOKIE|SERVER)|file_get_contents|curl_exec)",
            type=VulnerabilityType.WEBSHELL,
            level=RiskLevel.HIGH,
        ),
        Rule(
            id="w4",
            name="可疑系统指令反弹",
            pattern=r"(system|shell_exec|exec|passthru|popen|proc_open)\s*?\(.*?(\$_(POST|GET|REQUEST|COOKIE)|base64_decode)",
            type=VulnerabilityType.WEBSHELL,
            level=RiskLevel.CRITICAL,
        ),
        Rule(
            id="w5",
            name="冰蝎/蚁剑强特征",
            pattern=r"(@error_reporting|@set_time_limit|@ini_set).*?eval\s*?\(.*?base64_decode",
            type=VulnerabilityType.WEBSHELL,
            level=RiskLevel.CRITICAL,
        ),
    ]

    BUILT_IN_RULES: List[Rule] = WEBSHELL_REGEX_RULES

    def __init__(self):
        self._regex_cache: Dict[str, re.Pattern] = {}
        self._custom_rules: List[Rule] = []
        self._rule_states: Dict[str, bool] = {}
        self._php_parser = make_parser() if PHP_AST_AVAILABLE else None

    def get_effective_rules(self) -> List[Rule]:
        built_in_with_states = []
        for rule in self.WEBSHELL_REGEX_RULES:
            enabled = self._rule_states.get(rule.id, rule.enabled)
            built_in_with_states.append(
                Rule(
                    id=rule.id,
                    name=rule.name,
                    pattern=rule.pattern,
                    type=rule.type,
                    level=rule.level,
                    enabled=enabled,
                    is_built_in=True,
                )
            )

        all_rules = built_in_with_states + self._custom_rules
        return [r for r in all_rules if r.enabled]

    def get_compiled_regex(self, pattern: str, flags: int = re.IGNORECASE | re.DOTALL) -> re.Pattern:
        cache_key = (pattern, flags)
        if cache_key not in self._regex_cache:
            self._regex_cache[cache_key] = re.compile(pattern, flags)
        return self._regex_cache[cache_key]

    def _line(self, node: Any) -> int:
        try:
            ln = int(getattr(node, "lineno", 1) or 1)
            return max(1, ln)
        except Exception:
            return 1

    def _snippet(self, code_lines: List[str], lineno: int) -> str:
        if 1 <= lineno <= len(code_lines):
            return code_lines[lineno - 1].strip()[:300]
        return ""

    def _process_assignment(self, node: Any, tainted_vars: Dict[str, str]) -> None:
        lhs = getattr(node, "node", None) or getattr(node, "left", None)
        rhs = getattr(node, "expr", None) or getattr(node, "right", None)
        lhs_name = self._var_name(lhs)
        rhs_source = self._expr_taint(rhs, tainted_vars)
        if lhs_name:
            if rhs_source:
                tainted_vars[lhs_name] = rhs_source
            elif lhs_name in tainted_vars:
                tainted_vars.pop(lhs_name, None)

    def _is_ast_node(self, obj: Any) -> bool:
        return hasattr(obj, "__dict__") and obj.__class__.__module__.startswith("phply")

    def _iter_children(self, node: Any) -> Iterable[Any]:
        if not self._is_ast_node(node):
            return []
        children: List[Any] = []
        for value in node.__dict__.values():
            if isinstance(value, list):
                children.extend(value)
            else:
                children.append(value)
        return children

    def _walk(self, node: Any) -> Iterable[Any]:
        if node is None:
            return
        if isinstance(node, list):
            for item in node:
                yield from self._walk(item)
            return

        if self._is_ast_node(node):
            yield node
            for child in self._iter_children(node):
                yield from self._walk(child)

    def _var_name(self, node: Any) -> Optional[str]:
        if node is None:
            return None
        if isinstance(node, str):
            return node.lstrip("$")

        cls = node.__class__.__name__
        if cls == "Variable":
            name = getattr(node, "name", None)
            if isinstance(name, str):
                return name.lstrip("$")
            return self._var_name(name)

        for attr in ("node", "expr", "left", "var", "name"):
            if hasattr(node, attr):
                result = self._var_name(getattr(node, attr))
                if result:
                    return result
        return None

    def _source_from_superglobal(self, node: Any) -> Optional[str]:
        if node is None:
            return None

        cls = node.__class__.__name__
        if cls == "Variable":
            name = self._var_name(node)
            if name in self.SOURCE_SUPERGLOBALS:
                return f"$_{name[1:]}" if name.startswith("_") else f"${name}"

        if cls == "ArrayOffset":
            base = getattr(node, "node", None)
            base_name = self._var_name(base)
            if base_name in self.SOURCE_SUPERGLOBALS:
                return f"${base_name}"

        for child in self._iter_children(node) if self._is_ast_node(node) else []:
            found = self._source_from_superglobal(child)
            if found:
                return found

        return None

    def _call_name(self, node: Any) -> Optional[str]:
        if node is None:
            return None
        if isinstance(node, str):
            return node.lower()

        cls = node.__class__.__name__
        if cls in {"FunctionCall", "MethodCall", "StaticMethodCall"}:
            raw = getattr(node, "name", None)
            if isinstance(raw, str):
                return raw.lower()
            if self._is_ast_node(raw):
                name = self._var_name(raw)
                return name.lower() if name else None

        if cls == "Eval":
            return "eval"

        if cls == "Echo":
            return "echo"

        if cls == "Print":
            return "print"

        return None

    def _call_full_name(self, node: Any) -> Optional[str]:
        """返回 'class::method' 或 'obj->method' 形式，用于框架特定 Sink 匹配。"""
        if node is None:
            return None

        cls = node.__class__.__name__
        method_name = self._call_name(node)
        if not method_name:
            return None

        if cls == "StaticMethodCall":
            class_node = getattr(node, "class", None)
            class_name = ""
            if isinstance(class_node, str):
                class_name = class_node
            elif self._is_ast_node(class_node):
                class_name = getattr(class_node, "name", "") or self._var_name(class_node) or ""
            if class_name:
                return f"{class_name.lower()}::{method_name.lower()}"
            return method_name

        return method_name

    def _call_args(self, node: Any) -> List[Any]:
        if node is None:
            return []
        for attr in ("params", "args", "nodes", "expr"):
            if hasattr(node, attr):
                value = getattr(node, attr)
                if isinstance(value, list):
                    return value
                if value is not None:
                    return [value]
        return []

    def _expr_taint(self, expr: Any, tainted_vars: Dict[str, str], seen: Optional[Set[int]] = None) -> Optional[str]:
        if expr is None:
            return None
        if seen is None:
            seen = set()

        expr_id = id(expr)
        if expr_id in seen:
            return None
        seen.add(expr_id)

        source = self._source_from_superglobal(expr)
        if source:
            return source

        cls = expr.__class__.__name__ if not isinstance(expr, str) else "str"

        if cls == "Variable":
            vname = self._var_name(expr)
            if vname and vname in tainted_vars:
                return tainted_vars[vname]
            return None

        # 数组偏移：只要基变量被污染，任何下标都视为污点（简化但覆盖绝大多数场景）
        if cls == "ArrayOffset":
            base_name = self._var_name(expr)
            if base_name and base_name in tainted_vars:
                return tainted_vars[base_name]
            for child in self._iter_children(expr):
                child_src = self._expr_taint(child, tainted_vars, seen)
                if child_src:
                    return child_src
            return None

        if cls in {"FunctionCall", "MethodCall", "StaticMethodCall", "Eval"}:
            call_name = self._call_name(expr) or ""
            if call_name in self.SANITIZERS:
                return None
            if call_name in self.DYNAMIC_SOURCES:
                return f"{call_name}()"
            for arg in self._call_args(expr):
                arg_src = self._expr_taint(arg, tainted_vars, seen)
                if arg_src:
                    return arg_src
            return None

        if self._is_ast_node(expr):
            for child in self._iter_children(expr):
                child_src = self._expr_taint(child, tainted_vars, seen)
                if child_src:
                    return child_src

        return None

    def _dedup(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        seen: Set[Tuple[str, int, str]] = set()
        result: List[Vulnerability] = []
        for v in vulns:
            key = (v.type.value, v.line, v.sink)
            if key in seen:
                continue
            seen.add(key)
            result.append(v)
        return result

    def _has_pdo_binding(self, parsed: Any) -> bool:
        """检测 AST 中是否存在 PDO bindParam 或 execute(array(...)) 调用。"""
        for node in self._walk(parsed):
            call_name = self._call_name(node)
            if call_name == "bindparam":
                return True
            if call_name == "execute":
                args = self._call_args(node)
                for arg in args:
                    if arg.__class__.__name__ == "Array":
                        return True
        return False

    def _collect_magic_methods(self, parsed: Any) -> List[Tuple[Any, str]]:
        """收集 __wakeup / __destruct / __toString / __invoke 方法节点。"""
        methods: List[Tuple[Any, str]] = []
        for node in self._walk(parsed):
            if node.__class__.__name__ == "Method":
                method_name = getattr(node, "name", "")
                if method_name in {"__wakeup", "__destruct", "__toString", "__invoke"}:
                    methods.append((node, method_name))
        return methods

    def _scan_webshell_regex(self, file_name: str, code: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        lines = code.split("\n")
        rules = [r for r in self.get_effective_rules() if r.type == VulnerabilityType.WEBSHELL]

        for rule in rules:
            regex = self.get_compiled_regex(rule.pattern)
            for match in regex.finditer(code):
                line = code[: match.start()].count("\n") + 1
                sink = match.group(1) if match.lastindex and match.lastindex >= 1 else "webshell_pattern"
                snippet = self._snippet(lines, line) or match.group(0)[:300]
                vulns.append(
                    Vulnerability(
                        id=str(uuid.uuid4())[:9],
                        type=rule.type,
                        level=rule.level,
                        line=line,
                        file_name=file_name,
                        snippet=snippet,
                        description=f"[WEBSHELL后门特征] 命中规则“{rule.name}”，检测到可疑模式“{sink}”。",
                        source="特征命中",
                        sink=sink,
                    )
                )

        return self._dedup(vulns)

    def _scan_with_ast(self, file_name: str, code: str) -> List[Vulnerability]:
        if not PHP_AST_AVAILABLE or self._php_parser is None:
            return []

        parsed = self._php_parser.parse(code, lexer=php_lexer.clone(), debug=False)
        code_lines = code.split("\n")
        vulns: List[Vulnerability] = []
        tainted_vars: Dict[str, str] = {}

        has_pdo_binding = self._has_pdo_binding(parsed)
        magic_methods = self._collect_magic_methods(parsed)
        magic_ids: Set[int] = set()
        for method_node, _ in magic_methods:
            for child in self._walk(getattr(method_node, "nodes", [])):
                magic_ids.add(id(child))

        # 记录反序列化入口点 (line, func_name, source)
        deserialization_entries: List[Tuple[int, str, str]] = []

        # === 常规污点分析（跳过魔法方法体内的节点）===
        for node in self._walk(parsed):
            # 跳过魔法方法内部的节点，避免外部作用域被污染，也避免重复报告
            if id(node) in magic_ids:
                continue

            cls = node.__class__.__name__

            if "Assignment" in cls:
                self._process_assignment(node, tainted_vars)

            call_name = self._call_name(node)
            full_name = self._call_full_name(node)

            # 反序列化入口检测
            if call_name in {"unserialize", "json_decode", "yaml_parse"}:
                args = self._call_args(node)
                for arg in args:
                    source = self._expr_taint(arg, tainted_vars)
                    if source:
                        line = self._line(node)
                        deserialization_entries.append((line, call_name, source))
                        break

            # 动态方法调用检测
            is_dynamic_call = False
            if cls in {"MethodCall", "StaticMethodCall"}:
                raw_name = getattr(node, "name", None)
                if self._is_ast_node(raw_name) and raw_name.__class__.__name__ == "Variable":
                    is_dynamic_call = True

            if not call_name and not is_dynamic_call:
                continue

            # PDO prepare 误报修复
            if call_name == "prepare" and has_pdo_binding:
                continue

            spec = None
            if full_name:
                spec = self.SINKS.get(full_name) or self.SINKS.get(call_name)
            elif call_name:
                spec = self.SINKS.get(call_name)

            if spec:
                args = self._call_args(node)
                taint_source: Optional[str] = None
                if spec.require_taint:
                    for arg in args:
                        taint_source = self._expr_taint(arg, tainted_vars)
                        if taint_source:
                            break
                    if not taint_source:
                        continue
                else:
                    taint_source = "语义规则命中"

                line = self._line(node)
                snippet = self._snippet(code_lines, line)
                vulns.append(
                    Vulnerability(
                        id=str(uuid.uuid4())[:9],
                        type=spec.vuln_type,
                        level=spec.level,
                        line=line,
                        file_name=file_name,
                        snippet=snippet,
                        description=f"[AST数据流分析] 检测到不安全调用“{call_name or full_name}”，参数来源“{taint_source}”。",
                        source=taint_source,
                        sink=call_name or full_name or "",
                    )
                )

            if is_dynamic_call:
                args = self._call_args(node)
                for arg in args:
                    taint_source = self._expr_taint(arg, tainted_vars)
                    if taint_source:
                        line = self._line(node)
                        snippet = self._snippet(code_lines, line)
                        vulns.append(
                            Vulnerability(
                                id=str(uuid.uuid4())[:9],
                                type=VulnerabilityType.CODE_EXECUTION,
                                level=RiskLevel.CRITICAL,
                                line=line,
                                file_name=file_name,
                                snippet=snippet,
                                description=f"[AST数据流分析] 检测到动态方法调用，参数来源“{taint_source}”，存在远程代码执行风险。",
                                source=taint_source,
                                sink="动态方法调用",
                            )
                        )
                        break

        # === 魔法方法独立分析（POP 链）===
        pop_sinks: List[Vulnerability] = []
        for method_node, method_name in magic_methods:
            method_tainted: Dict[str, str] = {}
            for node in self._walk(getattr(method_node, "nodes", [])):
                cls = node.__class__.__name__

                if "Assignment" in cls:
                    self._process_assignment(node, method_tainted)

                call_name = self._call_name(node)
                full_name = self._call_full_name(node)

                is_dynamic_call = False
                if cls in {"MethodCall", "StaticMethodCall"}:
                    raw_name = getattr(node, "name", None)
                    if self._is_ast_node(raw_name) and raw_name.__class__.__name__ == "Variable":
                        is_dynamic_call = True

                if not call_name and not is_dynamic_call:
                    continue

                spec = None
                if full_name:
                    spec = self.SINKS.get(full_name) or self.SINKS.get(call_name)
                elif call_name:
                    spec = self.SINKS.get(call_name)

                if spec:
                    args = self._call_args(node)
                    taint_source = None
                    if spec.require_taint:
                        for arg in args:
                            taint_source = self._expr_taint(arg, method_tainted)
                            if taint_source:
                                break
                        if not taint_source:
                            continue
                    else:
                        taint_source = "语义规则命中"

                    line = self._line(node)
                    snippet = self._snippet(code_lines, line)
                    pop_sinks.append(
                        Vulnerability(
                            id=str(uuid.uuid4())[:9],
                            type=VulnerabilityType.DESERIALIZATION,
                            level=spec.level,
                            line=line,
                            file_name=file_name,
                            snippet=snippet,
                            description=f"[AST-POP链] {method_name} 触发不安全调用“{call_name or full_name}”，参数来源“{taint_source}”。",
                            source=taint_source,
                            sink=f"{method_name}::{call_name or full_name}",
                        )
                    )

                if is_dynamic_call:
                    args = self._call_args(node)
                    for arg in args:
                        taint_source = self._expr_taint(arg, method_tainted)
                        if taint_source:
                            line = self._line(node)
                            snippet = self._snippet(code_lines, line)
                            pop_sinks.append(
                                Vulnerability(
                                    id=str(uuid.uuid4())[:9],
                                    type=VulnerabilityType.DESERIALIZATION,
                                    level=RiskLevel.CRITICAL,
                                    line=line,
                                    file_name=file_name,
                                    snippet=snippet,
                                    description=f"[AST-POP链] {method_name} 内检测到动态方法调用，参数来源“{taint_source}”。",
                                    source=taint_source,
                                    sink=f"{method_name}::动态方法调用",
                                )
                            )
                            break

        vulns.extend(pop_sinks)

        # === POP 链总览：如果存在反序列化入口 + 魔法方法 Sink ===
        if deserialization_entries and pop_sinks:
            sink_names = sorted(set(v.sink for v in pop_sinks))
            for entry_line, entry_func, entry_source in deserialization_entries:
                vulns.append(
                    Vulnerability(
                        id=str(uuid.uuid4())[:9],
                        type=VulnerabilityType.DESERIALIZATION,
                        level=RiskLevel.CRITICAL,
                        line=entry_line,
                        file_name=file_name,
                        snippet=self._snippet(code_lines, entry_line),
                        description=f"[AST-POP链总览] 反序列化入口 {entry_func}(Line {entry_line}) → 魔法方法触发 {', '.join(sink_names)}，形成完整POP链。",
                        source=entry_source,
                        sink=f"{entry_func} → POP链",
                    )
                )

        return self._dedup(vulns)

    def _scan_with_regex_rules(self, file_name: str, code: str) -> List[Vulnerability]:
        """使用正则规则扫描（支持自定义规则）——仅用于常规模式，WebShell 扫描请使用 _scan_webshell_regex。"""
        vulns: List[Vulnerability] = []
        lines = code.split("\n")
        
        # 获取所有启用的规则（包括自定义规则）
        all_rules = self.get_effective_rules()
        

        # 仅保留非 WebShell 规则（WebShell 由 _scan_webshell_regex 处理）
        rules = [r for r in all_rules if r.type != VulnerabilityType.WEBSHELL]
        
        for rule in rules:
            try:
                # 使用更精确的正则编译（不使用DOTALL避免跨行匹配）
                regex = self.get_compiled_regex(rule.pattern, re.IGNORECASE)
                
                for match in regex.finditer(code):
                    line = code[: match.start()].count("\n") + 1
                    # 使用实际匹配的代码行作为snippet
                    snippet = lines[line - 1].strip() if 1 <= line <= len(lines) else match.group(0)[:300]
                    # 如果有捕获组，使用第一个非空捕获组作为sink
                    sink = rule.name
                    if match.lastindex and match.lastindex >= 1:
                        for i in range(1, match.lastindex + 1):
                            group_val = match.group(i)
                            if group_val:
                                sink = group_val[:50]  # 限制长度
                                break
                    
                    vulns.append(
                        Vulnerability(
                            id=str(uuid.uuid4())[:8],
                            type=rule.type,
                            level=rule.level,
                            line=line,
                            file_name=file_name,
                            snippet=snippet,
                            description=f"[规则命中] {rule.name}：检测到可疑模式 '{sink}'。",
                            source="正则规则匹配",
                            sink=sink,
                        )
                    )
            except Exception:
                continue
        
        return self._dedup(vulns)

    async def scan_file(self, file_name: str, code: str, is_webshell_mode: bool = False) -> List[Vulnerability]:
        """扫描单个文件：WebShell 使用特征模式，常规扫描优先 AST + 正则规则。"""
        if is_webshell_mode:
            return self._scan_webshell_regex(file_name, code)

        all_vulns: List[Vulnerability] = []
        
        # 1. 先尝试 AST 分析
        try:
            ast_vulns = self._scan_with_ast(file_name, code)
            all_vulns.extend(ast_vulns)
        except Exception:
            pass

        # 2. 再使用正则规则扫描（包括自定义规则）
        try:
            regex_vulns = self._scan_with_regex_rules(file_name, code)
            all_vulns.extend(regex_vulns)
        except Exception:
            pass

        return self._dedup(all_vulns)

    async def scan_project(
        self,
        files: List[Tuple[str, str]],
        is_webshell_mode: bool = False,
        progress_callback=None,
    ) -> List[Vulnerability]:
        all_vulnerabilities: List[Vulnerability] = []
        total_files = len(files)

        for i, (file_name, content) in enumerate(files):
            if progress_callback:
                await progress_callback(i, total_files, file_name)

            file_vulns = await self.scan_file(file_name, content, is_webshell_mode)
            all_vulnerabilities.extend(file_vulns)

        return self._dedup(all_vulnerabilities)

    def add_custom_rule(self, rule: Rule):
        self._custom_rules.append(rule)

    def remove_custom_rule(self, rule_id: str):
        self._custom_rules = [r for r in self._custom_rules if r.id != rule_id]

    def set_rule_state(self, rule_id: str, enabled: bool):
        """设置规则启用状态（用于内置规则）"""
        self._rule_states[rule_id] = enabled

    def get_rule_states(self) -> Dict[str, bool]:
        return self._rule_states.copy()
