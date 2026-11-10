# -*- coding: utf-8 -*-
"""工具即 CLI 子命令（批次104）：不进 MCP 客户端，也能从命令行 / shell / CI 调每个工具。

为什么需要
----------
本服务的工具此前**唯一的调用方式**是 MCP 客户端（stdio / Streamable HTTP）。这在三类
场景里用不上：

1. **人排障**：现场只想看一眼 ``get_status`` / ``read_mem`` / ``keil_health``，却要先
   配一个 MCP 客户端、拉起来、再说一句自然语言；
2. **脚本与 CI**：想「编译 → 烧录 → 读某地址 → 比对」串成一条命令，JSON-RPC 的会话态
   与帧格式不好嵌进 shell（想拿退出码、想 ``| grep``）；
3. **别的 Agent**：它们能跑命令，但未必接 MCP。

所以把「工具目录」与「工具调用」直接做成一等子命令：

    mdkdebug tools                        # 有哪些工具（分组 / 一句话 / 必填参数）
    mdkdebug tools --group build          # 只看某组
    mdkdebug groups                       # 有哪些组
    mdkdebug describe read_mem            # 一个工具的完整说明 + 参数表 + 调用示例
    mdkdebug call read_mem --arg addr=0x20000000 --arg n=16
    mdkdebug read_mem --arg addr=0x20000000 --arg n=16      # 省略 call 的简写

设计约束（与主服务同一套口径，不另造一套）
------------------------------------------
1. **默认服务端行为一个字不改**：``mdkdebug``（无参）、``--version``、``--host ...``
   全部照旧走原解析器。只有**第一个位置参数**是子命令名 / 工具名时才进这里。
2. **CLI 不是第二条实现**：它就是 ``server.call_tool``——参数别名归一、未知参数拒绝、
   统一结果信封（status / next_actions / error_code / risk）、输出控制
   （compact / max_lines / full）与 MCP 客户端调用**逐字节同一条路径**。
3. **退出码是给脚本用的**：0 = 成功，1 = 工具报错（结果 ``status=error`` 或框架
   ``is_error``），2 = 用法错误。**读不到就给非 0**，绝不静默成功。
4. **关得掉**：``MDKDEBUG_CLI=0`` 时本模块整体不上场，回到批次104 之前的纯服务端解析
   （未知位置参数仍旧报 argparse 错）。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

# 子命令名。工具名不会与它们撞车（这四个都不是工具）。
SUBCOMMANDS = ("tools", "groups", "describe", "call")

# 关掉 CLI 子命令层的取值（其余任何值/未设都算开）。
_OFF = {"0", "off", "false", "no", "disable", "disabled"}

# 一行摘要最长字符数：工具描述往往很长（含【参数】【调用示例】块），目录里只要判断句。
_SUMMARY_MAX = 96

# 描述里这些块是「给演示用」的，进目录时截掉。
_BLOCK_MARKS = ("\n【参数】", "\n【调用示例】", "\n【参数别名】", "\n【输出控制】",
                "\n【风险】", "\n【提示】", "\n【取回全文】")


def enabled() -> bool:
    """CLI 子命令层是否启用（``MDKDEBUG_CLI=0`` 关掉）。"""
    return str(os.environ.get("MDKDEBUG_CLI", "")).strip().lower() not in _OFF


def handles(argv) -> bool:
    """这批 argv 该不该由本模块处理。

    判据只有一条：**第一个参数不是选项**（不以 ``-`` 开头）。子命令名与工具名都是这种
    形态；而 ``--version`` / ``--host 1.2.3.4`` / 无参 都留给原解析器——尤其是
    ``--host 127.0.0.1`` 那一段，值虽然也不是选项但**位置在第二个**，所以不会被误吃。
    """
    if not enabled():
        return False
    argv = list(argv or [])
    if not argv:
        return False
    head = str(argv[0])
    return bool(head) and not head.startswith("-")


def coerce(text):
    """把命令行里的字符串还原成工具要的类型。

    先按 JSON 认（``16`` → int、``1.5`` → float、``true`` → bool、``null`` → None、
    ``[1,2]`` → list、``"abc"`` → str）；认不出来就**原样当字符串**——``0x20000000``
    这类十六进制字面量 JSON 不认，而本服务的工具普遍自己会解析 ``0x`` 前缀，交回原串
    才是对的（在这里强行转数字反而是「看似聪明的错答案」）。
    """
    if not isinstance(text, str):
        return text
    s = text.strip()
    if not s:
        return ""
    try:
        return json.loads(s)
    except Exception:  # noqa: BLE001
        return text


def _usage(msg: str):
    """用法错误：打到 stderr，退出码 2（与 argparse 一致，脚本可区分「用法错」与「工具错」）。"""
    print(msg, file=sys.stderr)
    raise SystemExit(2)


def parse_assignments(pairs) -> dict:
    """``--arg k=v`` 列表 → dict。值走 :func:`coerce`；键按原样保留（别名归一交给服务端）。"""
    out = {}
    for raw in pairs or []:
        s = str(raw)
        if "=" not in s:
            _usage("--arg 需要 k=v 形式，收到：%r" % s)
        k, v = s.split("=", 1)
        k = k.strip()
        if not k:
            _usage("--arg 的键不能为空：%r" % s)
        out[k] = coerce(v)
    return out


def load_args(spec) -> dict:
    """解析 ``--args``：内联 JSON，或 ``@文件``（UTF-8，容忍 BOM）。"""
    if not spec:
        return {}
    text = str(spec)
    if text.startswith("@"):
        path = text[1:]
        try:
            with open(path, "r", encoding="utf-8-sig") as fp:
                text = fp.read()
        except OSError as e:
            _usage("读不到 --args 文件 %s：%s" % (path, e))
    try:
        obj = json.loads(text)
    except Exception as e:  # noqa: BLE001
        _usage("--args 不是合法 JSON：%s" % e)
    if not isinstance(obj, dict):
        _usage("--args 必须是 JSON 对象（形如 {\"addr\": \"0x20000000\"}）")
    return obj


def _one_line(desc: str) -> str:
    """工具描述 → 一行摘要（截掉长块、压空白、超长加省略号）。"""
    text = str(desc or "")
    for mark in _BLOCK_MARKS:
        idx = text.find(mark)
        if idx > 0:
            text = text[:idx]
    text = " ".join(text.split())
    if len(text) > _SUMMARY_MAX:
        text = text[:_SUMMARY_MAX].rstrip() + "…"
    return text


def _group_of(name: str) -> str:
    """工具名 → 组名（未归组返回空串＝常驻）。每个工具最多归一组。"""
    from . import toolbox as _toolbox
    for gname, names in _toolbox.TOOLSETS.items():
        if name in names:
            return gname
    return ""


def _risk_of(name: str) -> str:
    from . import errors as _errors
    if name in _errors.RISK_HIGH:
        return "high"
    if name in _errors.RISK_MEDIUM:
        return "medium"
    return ""


def _schema_of(tool) -> dict:
    try:
        sch = getattr(tool, "input_schema", None)
        return sch if isinstance(sch, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _params_of(tool) -> list:
    """工具 → 参数清单（保持 schema 里的声明顺序）。"""
    sch = _schema_of(tool)
    props = sch.get("properties") or {}
    required = set(sch.get("required") or ())
    rows = []
    for pname, spec in props.items():
        spec = spec if isinstance(spec, dict) else {}
        typ = spec.get("type")
        if not typ and "anyOf" in spec:
            typ = "|".join(str((x or {}).get("type")) for x in spec["anyOf"])
        rows.append({
            "name": pname,
            "type": str(typ or ""),
            "required": pname in required,
            "default": spec.get("default", None),
            "has_default": "default" in spec,
            "description": _one_line(spec.get("description") or ""),
        })
    return rows


def _dump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str)


def _result_text(result) -> str:
    """CallToolResult → 文本（取第一条 text；没有就序列化 structured_content）。"""
    content = getattr(result, "content", None) or []
    for item in content:
        text = getattr(item, "text", None)
        if isinstance(text, str):
            return text
    sc = getattr(result, "structured_content", None)
    if sc is not None:
        return json.dumps(sc, ensure_ascii=False, default=str)
    return ""


def _is_error(result, text: str) -> bool:
    """判定这次调用是否失败：框架 is_error，或结果 JSON 里 status=error / ok=false。"""
    if getattr(result, "is_error", False):
        return True
    body = _try_json(text)
    if not isinstance(body, dict):
        return False
    if str(body.get("status", "")).lower() in ("error", "fail", "failed"):
        return True
    return body.get("ok") is False and ("error" in body)


def _try_json(text: str):
    s = str(text or "").strip()
    if s[:1] not in ("{", "["):
        return None
    try:
        return json.loads(s)
    except Exception:  # noqa: BLE001
        return None


# ----------------------------------------------------------------------
# 子命令实现
# ----------------------------------------------------------------------
async def _all_tools(server) -> list:
    """当前（已按 toolset 裁剪后的）工具清单。返回 wire 副本，只读用途。"""
    return list(await server.list_tools())


def _server(**kw):
    from .server import create_server
    return create_server(**kw)


async def cmd_tools(server, args) -> int:
    tools = await _all_tools(server)
    rows = []
    for t in tools:
        g = _group_of(t.name)
        if args.group and g != str(args.group).strip().lower():
            continue
        row = {
            "name": t.name,
            "group": g,
            "summary": _one_line(t.description),
            "required": [p["name"] for p in _params_of(t) if p["required"]],
            "risk": _risk_of(t.name),
        }
        if args.grep:
            hay = (row["name"] + " " + row["summary"]).lower()
            if str(args.grep).lower() not in hay:
                continue
        rows.append(row)
    rows.sort(key=lambda r: (r["group"], r["name"]))
    if args.limit and args.limit > 0:
        rows = rows[:args.limit]
    if args.json:
        print(_dump({"count": len(rows), "tools": rows}))
        return 0
    from . import toolbox as _toolbox
    cur = None
    for r in rows:
        if r["group"] != cur:
            cur = r["group"]
            note = _toolbox.GROUP_NOTES.get(cur) or ("常驻（未归组）" if not cur else "")
            print("\n== %s ==  %s" % (cur or "always", note))
        flags = []
        if r["required"]:
            flags.append("必填:" + ",".join(r["required"]))
        if r["risk"]:
            flags.append("风险:" + r["risk"])
        print("  %-28s %s%s" % (r["name"], r["summary"],
                                ("  [" + " ".join(flags) + "]") if flags else ""))
    print("\n共 %d 个工具（当前工具面）。看某组：mdkdebug tools --group <组名>；"
          "看某工具：mdkdebug describe <工具名>" % len(rows))
    return 0


async def cmd_groups(server, args) -> int:
    from . import toolbox as _toolbox
    tools = await _all_tools(server)
    visible = [t.name for t in tools]
    groups = []
    for g in sorted(_toolbox.TOOLSETS):
        members = sorted(_toolbox.TOOLSETS[g])
        groups.append({
            "name": g,
            "note": _toolbox.GROUP_NOTES.get(g, ""),
            "declared": len(members),
            "visible": len([n for n in members if n in visible]),
        })
    loose = [n for n in visible if not _group_of(n)]
    if args.json:
        print(_dump({"count": len(groups), "groups": groups,
                     "always_on": len(loose), "visible_tools": len(visible)}))
        return 0
    for g in groups:
        print("  %-11s %-3d 可见 %-3d  %s" % (g["name"], g["declared"], g["visible"],
                                             g["note"]))
    print("\n常驻（未归组）%d 个；当前工具面共 %d 个。" % (len(loose), len(visible)))
    print("装某组：调工具 tools_load(group=\"build\")，或启动前设 MDKDEBUG_TOOLSETS=all")
    return 0


async def cmd_describe(server, args) -> int:
    name = str(args.tool or "").strip()
    tools = {t.name: t for t in await _all_tools(server)}
    tool = tools.get(name)
    if tool is None:
        hits = [n for n in tools if name.lower() in n.lower()][:8]
        msg = "没有这个工具：%s" % name
        if hits:
            msg += "。相近的有：%s" % "、".join(hits)
        msg += "（用 mdkdebug tools 看全量）"
        print(msg, file=sys.stderr)
        return 2
    params = _params_of(tool)
    body = {
        "name": tool.name,
        "group": _group_of(tool.name),
        "risk": _risk_of(tool.name),
        "summary": _one_line(tool.description),
        "description": str(tool.description or ""),
        "params": params,
        "example": "mdkdebug call %s%s" % (
            tool.name,
            "".join(" --arg %s=%s" % (p["name"], _example_value(p))
                    for p in params if p["required"])),
    }
    if args.json:
        print(_dump(body))
        return 0
    print("%s   [组:%s%s]" % (body["name"], body["group"] or "常驻",
                              ("  风险:" + body["risk"]) if body["risk"] else ""))
    print("")
    print(body["description"].strip())
    if params:
        print("\n参数：")
        for p in params:
            tail = ""
            if p["has_default"]:
                tail = " 默认=%r" % (p["default"],)
            print("  %-22s %-10s %s%s%s" % (p["name"], p["type"],
                                            "必填  " if p["required"] else "可选  ",
                                            p["description"], tail))
    else:
        print("\n参数：无")
    print("\n调用示例：\n  %s\n  %s" % (body["example"], body["example"] + " --json"))
    return 0


def _example_value(p: dict) -> str:
    typ = (p.get("type") or "").lower()
    low = p["name"].lower()
    if "int" in typ:
        if "addr" in low:
            return "0x20000000"
        if low.endswith("_s") or "timeout" in low:
            return "5"
        return "16"
    if "bool" in typ:
        return "true"
    if "float" in typ or "number" in typ:
        return "1.0"
    if "array" in typ:
        return '"a,b"'
    return '"..."'


async def cmd_call(server, args) -> int:
    name = str(args.tool or "").strip()
    names = [t.name for t in await _all_tools(server)]
    if name not in names:
        hits = [n for n in names if name.lower() in n.lower()][:8]
        msg = "没有这个工具：%s" % name
        if hits:
            msg += "。相近的有：%s" % "、".join(hits)
        msg += "（用 mdkdebug tools 看全量）"
        print(msg, file=sys.stderr)
        return 2
    payload = load_args(args.args)
    payload.update(parse_assignments(args.arg))
    # 输出控制三件套：与 MCP 客户端传参完全同一条路径（server.call_tool 会摘出来）。
    if args.compact:
        payload["compact"] = True
    if args.full:
        payload["full"] = True
    if args.max_lines:
        payload["max_lines"] = int(args.max_lines)
    try:
        result = await server.call_tool(name, payload)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        # 参数名不被接受 / 未注册等都会走到这里（ToolError）。如实报，退出码非 0。
        print(json.dumps({"status": "error", "tool": name, "error": str(e)},
                         ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    text = _result_text(result)
    body = _try_json(text)
    if body is not None:
        print(_dump(body) if not args.raw else text)
    else:
        print(text)
    return 1 if _is_error(result, text) else 0


# ----------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mdkdebug",
        description=("mdkdebug —— 工具即子命令。不带位置参数＝按 MCP Server 运行（原行为）；"
                     "给子命令或工具名＝命令行直调。"),
        epilog=("例：mdkdebug tools --group build | mdkdebug describe read_mem | "
                "mdkdebug read_mem --arg addr=0x20000000 --arg n=16"),
    )
    from . import __version__
    parser.add_argument("--version", action="version",
                        version="mdkdebug %s (cli)" % __version__)
    # 与主入口同名的服务端配置项：命令行直调也要能指定 Keil/UVSOCK/符号。
    g = parser.add_argument_group("服务端配置（与 mdkdebug 服务一致）")
    g.add_argument("--host", default="127.0.0.1", help="UVSOCK 主机 (默认 127.0.0.1)")
    g.add_argument("--port", type=int, default=4823, help="UVSOCK 端口 (默认 4823)")
    g.add_argument("--idle-timeout", type=float, default=30.0, help="连接缓存空闲秒数")
    g.add_argument("--uv4-path", default=None, help="Keil UV4.exe 绝对路径")
    g.add_argument("--default-project", default=None, help="默认 .uvprojx 路径")
    g.add_argument("--axf-path", default=None, help="调试符号 .axf 路径")
    g.add_argument("--toolsets", default=None,
                   help="工具面（组名逗号分隔，或 all）——覆盖 MDKDEBUG_TOOLSETS")
    g.add_argument("--verbose", action="store_true", help="输出调试日志")

    sub = parser.add_subparsers(dest="cmd", metavar="<子命令或工具名>")

    p = sub.add_parser("tools", help="列出工具（分组 / 一句话 / 必填参数）")
    p.add_argument("--group", default=None, help="只看某组（core/mem/build/...）")
    p.add_argument("--grep", default=None, help="按名字或摘要过滤（不区分大小写）")
    p.add_argument("--limit", type=int, default=0, help="最多列 N 条（0=全部）")
    p.add_argument("--json", action="store_true", help="机器可读输出")

    p = sub.add_parser("groups", help="列出工具分组")
    p.add_argument("--json", action="store_true", help="机器可读输出")

    p = sub.add_parser("describe", help="看一个工具的完整说明与参数表")
    p.add_argument("tool", help="工具名")
    p.add_argument("--json", action="store_true", help="机器可读输出")

    p = sub.add_parser("call", help="调用一个工具（参数走 --args / --arg k=v）")
    p.add_argument("tool", help="工具名")
    p.add_argument("--args", default=None,
                   help="参数 JSON 对象，或 @文件（UTF-8，容忍 BOM）")
    p.add_argument("--arg", action="append", default=[], metavar="K=V",
                   help="单个参数，可重复；值按 JSON 认（认不出当字符串，0x.. 原样交出）")
    p.add_argument("--json", action="store_true",
                   help="显式声明（调用结果本来就是 JSON，保留以便脚本自述）")
    p.add_argument("--raw", action="store_true", help="原样打印工具文本，不重排缩进")
    p.add_argument("--compact", action="store_true", help="转发输出控制 compact")
    p.add_argument("--full", action="store_true", help="转发输出控制 full（不裁剪）")
    p.add_argument("--max-lines", type=int, default=0, help="转发输出控制 max_lines")
    return parser


def _normalize_argv(argv) -> list:
    """``mdkdebug read_mem ...`` → ``mdkdebug call read_mem ...``（简写归一）。"""
    argv = list(argv or [])
    if not argv:
        return argv
    head = str(argv[0])
    if head.startswith("-") or head in SUBCOMMANDS:
        return argv
    return ["call"] + argv


def main(argv=None) -> int:
    argv = _normalize_argv(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    ns = parser.parse_args(argv)
    if not ns.cmd:
        parser.print_help()
        return 2
    import logging
    # 默认只报 ERROR：`create_server` 在没配 .axf 时会 WARNING 一句「位置定位工具不可用」，
    # 那是正常态，不该在每条 CLI 命令的 stderr 上重复刷屏（工具级错误都在返回体里）。
    logging.basicConfig(level=logging.DEBUG if ns.verbose else logging.ERROR,
                        format="%(levelname)s %(name)s - %(message)s",
                        stream=sys.stderr)
    server = _server(host=ns.host, port=ns.port, idle_timeout=ns.idle_timeout,
                     uv4_path=ns.uv4_path, default_project=ns.default_project,
                     axf_path=ns.axf_path, toolsets=ns.toolsets)
    handler = {"tools": cmd_tools, "groups": cmd_groups,
               "describe": cmd_describe, "call": cmd_call}[ns.cmd]
    try:
        return asyncio.run(handler(server, ns))
    except KeyboardInterrupt:
        return 130
