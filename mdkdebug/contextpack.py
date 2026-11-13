# -*- coding: utf-8 -*-
"""单函数「写 C 的证据包」（批次107）。

这个模块回答的问题是：**要给一个函数写出等价的 C，手上到底有哪些证据？**

答案是分层的，而且每一层的可信度不同——把它们混成一段文字，写 C 的人（人或 AI）
就会把「推断」当「观察」用：

  1. **观察**：反汇编（带机器码）、符号表里的名字/大小/绑定、DWARF 的文件与行号、
     字面量池里的字符串；
  2. **推断**：伪 C（寄存器级 lifting，表达式与控制流保真，类型是猜的）、
     栈槽位表、结构体候选（基址寄存器值未知的访存按 ``base_reg + offset`` 聚合）、
     调用者/被调用者清单；
  3. **缺口**：这四类**都给不出**的东西必须逐条写出来，而不是沉默——
     ``unavailable``（镜像里压根没有，比如被 strip 掉的调试信息）、
     ``unsupported``（有但本工具不做，比如 DWARF 的参数类型）、
     ``query_failed``（查询出错）、``unresolved_call``（间接调用解不出目标）、
     ``limit``（撞到输出上限）。

为什么要单独一条工具：``recover_disasm`` 给汇编、``recover_lift`` 给伪 C、
``recover_xref`` 给交叉引用——但写一个函数需要的是**这几样按同一个函数对齐后放在一起**，
并且明确「参数类型我们不知道」。少一句「不知道」，写出来的 C 就会多一个瞎编的 ``int``。
"""
from __future__ import annotations

import os

from . import plan as _plan
from . import recover as _recover
from . import reveng as _reveng
from . import rtypes as _rtypes

# 证据包文本的默认上限（字符）：再多就不是「一次能读完的证据」，而需要分页
DEFAULT_MAX_CHARS = 60000
# 一次返回的反汇编条数上限
MAX_ASM_INSNS = 2000

# 缺口五类：词表固定，别让每一处自己发明说法
GAP_KINDS = ("unavailable", "unsupported", "query_failed", "unresolved_call", "limit")


def _gap(kind: str, what: str, *, detail: str = "", origin: str = "") -> dict:
    if kind not in GAP_KINDS:
        raise ValueError("未知缺口类别：%r（只有这五类：%s）"
                         % (kind, " / ".join(GAP_KINDS)))
    return {"kind": kind, "what": what, "detail": detail, "origin": origin}


def _find_function(funcs: list, target: int, symbol: str) -> tuple:
    """按地址或**精确**符号名找函数。两者都给时以地址为准。"""
    if target:
        a = int(target) & ~1
        hit = next((f for f in funcs if int(f["addr"]) == a), None)
        if hit:
            return hit, ""
        near = sorted(funcs, key=lambda f: abs(int(f["addr"]) - a))[:5]
        return None, ("地址 0x%08X 不是任何已知函数入口；最近的入口：%s"
                      % (a, ", ".join("%s(0x%08X)" % (f.get("name"), int(f["addr"]))
                                      for f in near)))
    if symbol:
        hit = next((f for f in funcs if str(f.get("name") or "") == symbol), None)
        if hit:
            return hit, ""
        sub = [str(f.get("name") or "") for f in funcs
               if symbol.lower() in str(f.get("name") or "").lower()][:12]
        return None, ("符号 %r 不是任何已知函数的名字（要**精确**名字）；"
                      "含该子串的：%s" % (symbol, ", ".join(sub) if sub else "（无）"))
    return None, "必须给 target（地址）或 symbol（精确函数名）之一——工具不猜你要哪个函数"


def _asm_rows(insns: list, names: dict) -> list:
    rows = []
    for ins in insns:
        tgt = ins.get("target")
        row = {"addr_hex": ins.get("addr_hex"),
               "mnemonic": ins.get("mnemonic"),
               "op_str": ins.get("op_str"),
               "bytes": ins.get("bytes")}
        if tgt is not None:
            t = int(tgt) & ~1
            row["target_hex"] = "0x%08X" % t
            nm = names.get(t)
            if nm:
                row["target_name"] = nm
        rows.append(row)
    return rows


def _asm_text(rows: list) -> str:
    out = []
    for r in rows:
        tail = ""
        if r.get("target_name"):
            tail = "   ; %s" % r["target_name"]
        elif r.get("target_hex"):
            tail = "   ; -> %s" % r["target_hex"]
        out.append("%s  %-8s %-8s %-28s%s" % (r["addr_hex"], r.get("bytes") or "",
                                              r.get("mnemonic") or "",
                                              r.get("op_str") or "", tail))
    return "\n".join(out)


def pack(path: str, target: str | int = 0, symbol: str = "", base: int = 0, *,
         max_chars: int = DEFAULT_MAX_CHARS, max_insns: int = MAX_ASM_INSNS,
         include_c: bool = True, include_asm: bool = True) -> dict:
    """给一个函数出「写 C 的证据包」。

    ``target`` 是地址（可带 Thumb 位），``symbol`` 是**精确**函数名；两者给一个。
    ``max_chars`` 是文本上限：超了就按段裁剪（先砍反汇编尾巴），并记一条 ``limit`` 缺口。
    """
    path = str(path or "").strip()
    if not path:
        return {"ok": False, "error": "缺少 path"}
    try:
        addr = int(str(target).strip(), 0) if isinstance(target, str) else int(target or 0)
    except ValueError:
        return {"ok": False, "error": "target 必须是地址（0x080030B0 / 十进制），收到 %r" % target}

    an = _recover.analyze(path, base=int(base or 0), deep=True)
    unit = an.get("_unit")
    an.pop("_unit", None)
    an.pop("_recover", None)
    if not an.get("ok"):
        return an
    if unit is None:
        return {"ok": False, "error": "内部错误：剖析没有给出可寻址的镜像"}
    r = _recover.recover_functions(unit, deep=True)
    if not r.get("ok"):
        return r
    funcs = r.get("functions") or []
    gaps = []
    if r.get("truncated"):
        gaps.append(_gap("limit", "函数清单被截断",
                         detail="函数数超过上限，本函数可能不在清单里",
                         origin="recover_functions"))

    f, why = _find_function(funcs, addr, str(symbol or "").strip())
    if f is None:
        return {"ok": False, "error": why,
                "function_count": len(funcs),
                "hint": "先用 recover_plan 看清单，或用 recover_functions 找名字"}
    start = int(f["addr"])
    end = int(f.get("end_addr") or 0)
    if end <= start:
        end = start + max(int(f.get("size") or 0), 4)
    names = {int(x["addr"]): str(x.get("name") or "") for x in funcs}

    # ---- 观察：反汇编 ----
    d = _recover.disassemble(unit, start, end, max_insns=int(max_insns or MAX_ASM_INSNS))
    insns, asm_rows, asm_text = {}, [], ""
    if d.get("ok"):
        insns = {int(i["addr"]): i for i in d["insns"]}
        if include_asm:
            asm_rows = _asm_rows(d["insns"], names)
            asm_text = _asm_text(asm_rows)
        if d.get("truncated"):
            gaps.append(_gap("limit", "反汇编被截断",
                             detail="超过 max_insns=%d 条" % int(max_insns or MAX_ASM_INSNS),
                             origin="recover.disassemble"))
    else:
        gaps.append(_gap("query_failed", "反汇编失败",
                         detail=str(d.get("error") or ""), origin="recover.disassemble"))

    # ---- 推断：栈槽位 / 结构体候选 / 交叉引用（只在函数内做常量传播） ----
    stack_slots, structs, strings, unresolved = [], [], [], []
    if insns:
        try:
            sf = _rtypes.stack_frame(insns, start, end)
            stack_slots = sf.get("slots") or []
        except Exception as e:  # noqa: BLE001
            gaps.append(_gap("query_failed", "栈槽位分析失败", detail=str(e),
                             origin="rtypes.stack_frame"))
        try:
            xr = _reveng.build_xrefs(unit, insns, [dict(f, start=start, end_addr=end)])
            unresolved = xr.get("unresolved") or []
            try:
                sc = _rtypes.struct_candidates(unresolved, insns,
                                              [dict(f, end_addr=end)])
                one = next((x for x in (sc.get("functions") or [])
                            if int(x.get("func") or 0) == start), None)
                structs = (one or {}).get("candidates") or []
            except Exception as e:  # noqa: BLE001
                gaps.append(_gap("query_failed", "结构体候选聚合失败", detail=str(e),
                                 origin="rtypes.struct_candidates"))
            if xr.get("truncated"):
                gaps.append(_gap("limit", "交叉引用被截断", origin="reveng.build_xrefs"))
        except Exception as e:  # noqa: BLE001
            gaps.append(_gap("query_failed", "交叉引用分析失败", detail=str(e),
                             origin="reveng.build_xrefs"))
        ind = [u for u in unresolved if u.get("kind") == "call_indirect"]
        if ind:
            gaps.append(_gap(
                "unresolved_call",
                "有 %d 处间接调用（blx/bx 寄存器）解析不出目标" % len(ind),
                detail="这些调用的被调者只能靠别的手段确认（运行时断点 / 交叉引用表）；"
                       "写 C 时不要假设它一定是什么",
                origin="reveng.build_xrefs"))
    strings = [{"from_hex": s.get("from_hex"), "to_hex": s.get("to_hex"),
                "text": s.get("text")}
               for s in (r.get("string_refs") or [])
               if start <= int(s.get("from") or 0) < end]

    # ---- 推断：伪 C ----
    pseudo, pc_notes = None, []
    if include_c:
        from . import decomp as _decomp           # noqa: PLC0415
        allf = [{"addr": int(x["addr"]),
                 "end_addr": int(x.get("end_addr") or x["addr"]),
                 "name": x.get("name")} for x in funcs]
        one = _decomp.decompile_function(
            unit, {"addr": start, "end_addr": end, "name": f.get("name")},
            funcs=allf, names=names, max_insns=int(max_insns or MAX_ASM_INSNS))
        if one.get("ok"):
            pseudo = {"code": one.get("code"),
                      "n_insns": one.get("n_insns"), "n_blocks": one.get("n_blocks"),
                      "notes": one.get("notes") or [],
                      "unsupported": one.get("unsupported") or []}
            pc_notes = pseudo["notes"]
            for u in (one.get("unsupported") or []):
                gaps.append(_gap("unsupported", "伪 C 有未支持的结构",
                                 detail=str(u), origin="decomp"))
        else:
            gaps.append(_gap("unsupported", "伪 C 生成失败（不影响汇编与其它证据）",
                             detail=str(one.get("error") or ""), origin="decomp"))

    # ---- 调用关系 ----
    callers = [{"addr_hex": "0x%08X" % int(a), "name": names.get(int(a)) or ""}
               for a in (f.get("callers") or [])]
    callees = []
    for a in (f.get("call_targets") or []):
        a = int(a) & ~1
        callees.append({"addr_hex": "0x%08X" % a, "name": names.get(a) or "",
                        "in_image": a in names})
    n_ext = sum(1 for c in callees if not c["in_image"])
    if n_ext:
        gaps.append(_gap("unavailable", "有 %d 个被调者不在已知函数清单里" % n_ext,
                         detail="它们是库函数、未识别代码或间接目标；"
                                "写 C 时按已知原型调用，不要因为「看不到实现」就猜它的行为",
                         origin="recover_functions"))

    # ---- DWARF：只有文件与行号，没有参数类型 ----
    dwarf = {"file": f.get("file") or "", "line": f.get("line")}
    if dwarf["file"]:
        gaps.append(_gap("unsupported", "DWARF 只给到文件名与行号，不给参数/返回类型",
                         detail="参数个数与返回值是 AAPCS 推断（%s），不是类型信息"
                                % (f.get("arg_basis") or "无依据"),
                         origin="recover.dwarf_info"))
    else:
        gaps.append(_gap("unavailable", "没有这个函数的 DWARF 位置信息",
                         detail="镜像可能被 strip，或该函数由汇编/库提供",
                         origin="recover.dwarf_info"))

    out = {
        "ok": True,
        "artifact_kind": "context",
        "evidence_only": True,
        "identity": {"path": an.get("path"), "name": os.path.basename(path),
                     "size": an.get("size"), "sha256": an.get("sha256"),
                     "base": int(base or 0), "tool_version": _plan.tool_version()},
        "function": {
            "addr": start, "addr_hex": "0x%08X" % start,
            "end_hex": "0x%08X" % end, "size_bytes": end - start,
            "name": f.get("name"), "confidence": f.get("confidence"),
            "sources": f.get("sources"), "body_basis": f.get("body_basis"),
            "params_estimate": f.get("params_estimate"),
            "returns_estimate": f.get("returns_estimate"),
            "arg_basis": f.get("arg_basis"),
            "n_callers": f.get("n_callers"), "n_cases": f.get("n_cases"),
            "frame_span": f.get("frame_span"),
            "dwarf": dwarf,
        },
        "asm": {"text": asm_text, "instructions": asm_rows,
                "n_insns": len(asm_rows), "format": "addr  bytes  mnemonic  operands"},
        "pseudo_c": pseudo,
        "callers": callers,
        "callees": callees,
        "stack_slots": stack_slots,
        "structs": structs,
        "strings": strings,
        "gaps": gaps,
        "next_actions": [
            "按 asm 与 pseudo_c 写出候选 C（pseudo_c 的类型是猜的，参数按 params_estimate 起步）",
            "写完跑 recover_c_check（源码与汇编的结构体检），再用 recover_c_build 回编译比对",
            "gaps 里 unresolved_call / unavailable 的项不要凭印象补，缺什么就写 TODO 注释",
        ],
        "caveats": [
            "pseudo_c 是寄存器级 lifting：表达式与控制流保真，类型名与变量名是**推断**",
            "函数体边界来自「到终止指令为止」，尾调用/内联会让边界与源码不一致",
            "参数用的是 AAPCS 推断（首次访问为读），不是签名",
        ],
    }

    # ---- 上限：先砍反汇编尾巴，再砍伪 C ----
    limit_n = max(2000, int(max_chars or DEFAULT_MAX_CHARS))
    def _size() -> int:
        return len(asm_text) + len((pseudo or {}).get("code") or "")
    if _size() > limit_n and asm_rows:
        keep = len(asm_rows)
        while keep > 40 and _size() > limit_n:
            keep = int(keep * 0.8)
            asm_rows = asm_rows[:keep]
            asm_text = _asm_text(asm_rows)
            out["asm"]["instructions"] = asm_rows
            out["asm"]["text"] = asm_text
            out["asm"]["n_insns"] = len(asm_rows)
            out["asm"]["truncated"] = True
        if out["asm"].get("truncated"):
            gaps.append(_gap("limit", "证据包超 %d 字符：反汇编被裁到 %d 条"
                             % (limit_n, len(asm_rows)),
                             detail="要完整的请用 recover_disasm 单独看这个函数",
                             origin="contextpack"))
    if _size() > limit_n and pseudo:
        code = pseudo.get("code") or ""
        pseudo["code"] = code[:max(2000, limit_n - len(asm_text))]
        pseudo["truncated"] = True
        gaps.append(_gap("limit", "证据包超上限：伪 C 被截断",
                         detail="用 start/end 分段取，或单独看 recover_lift",
                         origin="contextpack"))
    out["chars"] = {"asm": len(out["asm"]["text"]),
                    "pseudo_c": len((out.get("pseudo_c") or {}).get("code") or ""),
                    "limit": limit_n}
    out["gaps"] = gaps
    return out
