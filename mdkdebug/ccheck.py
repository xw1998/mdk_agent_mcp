# -*- coding: utf-8 -*-
"""候选 C 的结构体检（批次107）——「写完了先自己看一眼，别等到上板才发现对不上」。

这不是编译器，也不是等价性证明。它做的是**保守的结构比对**：把「候选 C 里能数出来的东西」
和「这个函数在镜像里的汇编能数出来的东西」摆在一起，只在**强不匹配**时判失败。

为什么必须保守：源码里一个 ``for`` 循环可以变成 0 个、1 个或多个回边（编译器展开、
把循环变成 do-while、或者干脆用条件跳转拼出来）；一个 ``if`` 可能被折叠成 ``it`` 块
或者用条件指令。**结构数对不上不等于写错了**，但「汇编里有 12 条调用、源码里一个函数都没调」
这种就基本一定写错了。所以判词分三档：

  * ``strong_mismatch`` —— 有硬证据说明这份 C 不是这段机器码：
      常量返回 vs 一堆调用/循环；汇编里有 N 条 ``bl`` 而源码里 0 次调用；
      汇编用了浮点/VFP 而源码里没有浮点；汇编有回边（循环）而源码里没有循环结构。
  * ``weak_mismatch``   —— 数值对不上但可能只是编译策略（调用数差 1~2、
      分支数差一个量级、源码里有 TODO/stub 标记而函数体不小）。
  * ``no_obvious_mismatch`` —— 没抓到强不匹配（**不是**「等价」）。

修错环的状态是 ``state`` 文件：记 ``attempts`` 与每轮的判词，超过 ``max_attempts``
就直接拒绝（不让同一个函数被无限重试烧掉预算）。状态文件只记次数与判词名，
不记源码 —— 源码属于调用方。
"""
from __future__ import annotations

import json
import os
import re

from . import evidence as _evidence
from . import recover as _recover
from . import textio as _textio

MAX_ATTEMPTS = 6

# 源码里算「调用」的写法：标识符后接 (；关键字与类型转换不算
_C_KEYWORDS = {
    "if", "else", "for", "while", "do", "switch", "case", "default", "return",
    "sizeof", "goto", "break", "continue", "typedef", "struct", "union", "enum",
    "static", "const", "volatile", "extern", "inline", "unsigned", "signed",
    "void", "char", "short", "int", "long", "float", "double", "bool", "_Bool",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t",
    "int32_t", "int64_t", "size_t", "define", "defined", "ifdef", "ifndef",
    "elif", "endif", "include", "pragma", "error",
}
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_LOOP_RE = re.compile(r"\b(for|while|do)\b")
_IF_RE = re.compile(r"\bif\b")
_SWITCH_RE = re.compile(r"\bswitch\b")
_CASE_RE = re.compile(r"\bcase\b")
_RET_RE = re.compile(r"\breturn\b\s*([^;]*);")
_CONST_RET_RE = re.compile(
    r"\breturn\b\s*(\(\s*)?(-?(?:0[xX][0-9A-Fa-f]+|\d+)[uUlL]*)\s*\)?\s*;")
_FP_RE = re.compile(r"\b(float|double)\b|\d+\.\d+[fF]?\b")
_NAN_RE = re.compile(r"\b(isnan|isinf|NAN|INFINITY|nanf?)\b")
_STUB_RE = re.compile(r"\b(TODO|FIXME|XXX|stub|unimplemented|not\s+implemented|"
                      r"placeholder|dummy)\b", re.I)
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
# 函数定义/声明：`<返回类型> <名字>(`。定义本身**不是**一次调用——不认出来就会把
# 「源码里定义了 HAL_GPIO_TogglePin」数成「源码调了 HAL_GPIO_TogglePin」，
# 于是 6 条指令的短函数会被 ① 号规则误判成常量返回（真实踩到的假阳性）。
_DEF_RE = re.compile(r"^[ \t]*(?:[A-Za-z_]\w*[\s\*]+)+([A-Za-z_]\w*)\s*\(",
                     re.M)

# 汇编里算浮点的助记符前缀（ARM VFP / NEON 标量）
_FP_MNEMONIC = ("vadd", "vsub", "vmul", "vdiv", "vsqrt", "vldr", "vstr", "vmov",
                "vcvt", "vcmp", "vneg", "vabs", "vmrs", "vmsr")
_CALL_MNEMONIC = ("bl", "blx")
# 以 b 开头但不是分支的助记符（位域操作/断点/调用已单独处理）
_NOT_BRANCH = {"bl", "blx", "bic", "bics", "bfi", "bfc", "bkpt", "bx"}


def _strip_comments(code: str) -> str:
    return _COMMENT_RE.sub(" ", code or "")


def _src_stats(code: str) -> dict:
    """从候选 C 里数出可比的结构量。**正则级**，不建 AST。"""
    body = _strip_comments(code)
    lines = [ln for ln in body.splitlines() if ln.strip()]
    # 把「定义处那个名字」从调用计数里剔掉（只剔名字本身，不动别的调用）
    masked, cut = body, 0
    for m in _DEF_RE.finditer(body):
        name = m.group(1)
        if name in _C_KEYWORDS:
            continue
        at = m.start(1) - cut
        masked = masked[:at] + " " * len(name) + masked[at + len(name):]
        cut += len(name)
    calls = [m.group(1) for m in _CALL_RE.finditer(masked)
             if m.group(1) not in _C_KEYWORDS]
    rets = _RET_RE.findall(body)
    const_ret = _CONST_RET_RE.search(body) is not None
    return {
        "lines": len(lines),
        "chars": len(code or ""),
        "calls": len(calls),
        "call_names": sorted(set(calls)),
        "loops": len(_LOOP_RE.findall(body)),
        "ifs": len(_IF_RE.findall(body)),
        "switches": len(_SWITCH_RE.findall(body)),
        "cases": len(_CASE_RE.findall(body)),
        "returns": len(rets),
        "constant_return_only": bool(const_ret) and len(rets) == 1 and not calls
                                 and not _LOOP_RE.search(body),
        "float": len(_FP_RE.findall(body)),
        "nan": len(_NAN_RE.findall(body)),
        "stub_marker": bool(_STUB_RE.search(body)),
    }


def _asm_stats(insns: list) -> dict:
    calls, branches, back = 0, 0, 0
    fp, rets = 0, 0
    mnemos = {}
    for i, ins in enumerate(insns):
        m = (ins.get("mnemonic") or "").lower()
        mnemos[m] = mnemos.get(m, 0) + 1
        if m in _CALL_MNEMONIC:
            calls += 1
        elif m.startswith("b") and m not in _NOT_BRANCH:
            # b / b<cond> / cbz / cbnz / tbb / bx：都算「分支」；
            # bl/blx 已在上面记成调用，bic/bfi/bfc/bkpt 不是分支。
            branches += 1
            tgt = ins.get("target")
            if tgt is not None and (int(tgt) & ~1) < int(ins.get("addr") or 0):
                back += 1
        if m.startswith(_FP_MNEMONIC):
            fp += 1
        if m in ("pop", "bx") and "pc" in (ins.get("op_str") or ""):
            rets += 1
    return {"n_insns": len(insns), "calls": calls, "branches": branches,
            "backward_branches": back, "fp": fp, "returns": rets,
            "mnemonics": mnemos}


def _signals(src: dict, asm: dict) -> list:
    """把差异变成带严重度的信号清单。**只用强证据判 strong**。"""
    sig = []

    def add(name, severity, detail):
        sig.append({"signal": name, "severity": severity, "detail": detail})

    # ① 常量返回：汇编很小却没有调用，而源码在调别人/有循环
    if asm["n_insns"] <= 6 and (src["calls"] or src["loops"] or src["ifs"]):
        add("const_vs_code", "strong",
            "汇编只有 %d 条指令（常量返回/stub 的典型形态），源码却有 %d 次调用、"
            "%d 个循环、%d 个 if" % (asm["n_insns"], src["calls"], src["loops"], src["ifs"]))
    elif asm["n_insns"] > 40 and src["constant_return_only"]:
        add("code_vs_const", "strong",
            "源码只返回一个常量，汇编却有 %d 条指令" % asm["n_insns"])

    # ② 调用数：汇编有 bl，源码一个调用都没有（或反之）
    if asm["calls"] >= 2 and src["calls"] == 0:
        add("asm_calls_not_in_source", "strong",
            "汇编里有 %d 条 bl，源码里 0 次函数调用——把调用漏了"
            % asm["calls"])
    elif src["calls"] >= 2 and asm["calls"] == 0:
        add("source_calls_not_in_asm", "strong",
            "源码调了 %d 个函数，汇编里没有任何 bl——调用的东西可能被内联，"
            "也可能写的不是这段代码" % src["calls"])
    elif abs(src["calls"] - asm["calls"]) >= 3:
        add("call_count_gap", "weak",
            "调用数差得远：源码 %d、汇编 %d（内联/尾调用能解释一部分）"
            % (src["calls"], asm["calls"]))

    # ③ 循环：汇编有回边而源码没有任何循环结构（或反之）
    if asm["backward_branches"] >= 1 and src["loops"] == 0 and src["switches"] == 0:
        add("asm_loop_not_in_source", "strong",
            "汇编里有 %d 条回边（循环）而源码里没有任何 for/while/do"
            % asm["backward_branches"])
    elif src["loops"] >= 1 and asm["backward_branches"] == 0 and asm["switches"] == 0:
        add("source_loop_not_in_asm", "strong",
            "源码里有 %d 个循环结构，汇编里 0 条回边（全被展开的话也可能）"
            % src["loops"])

    # ④ 浮点 / NaN
    if asm["fp"] and src["float"] == 0:
        add("asm_fp_not_in_source", "strong",
            "汇编有 %d 条 VFP/浮点指令，源码里没有 float/double" % asm["fp"])
    if src["nan"] and not asm["branches"]:
        add("nan_without_branch", "weak",
            "源码里判 NaN，但汇编里没有分支（判 NaN 至少要一条比较+条件跳转）")

    # ⑤ 体量与 stub
    if src["stub_marker"] and asm["n_insns"] > 12:
        add("stub_marker", "weak",
            "源码里有 TODO/stub/placeholder 标记，但这个函数在镜像里有 %d 条指令"
            % asm["n_insns"])
    if asm["n_insns"] >= 60 and src["lines"] <= 3:
        add("stub_for_big_function", "strong",
            "汇编 %d 条指令，源码只有 %d 行——基本是拿 stub 顶的"
            % (asm["n_insns"], src["lines"]))
    elif asm["n_insns"] >= 20 and src["lines"] == 1 and src["calls"] == 0:
        add("thin_source", "weak",
            "汇编 %d 条指令，源码只有 1 行且没有调用" % asm["n_insns"])

    # ⑥ 分支数粗比（允许编译策略造成的 4 倍偏差）
    if src["ifs"] + src["switches"] + src["loops"] == 0 and asm["branches"] >= 6:
        add("branches_not_in_source", "weak",
            "汇编有 %d 条分支，源码里没有任何 if/switch/循环" % asm["branches"])
    return sig


def _load_state(state: str) -> dict:
    if not state or not os.path.isfile(state):
        return {"attempts": 0, "history": []}
    try:
        with open(state, "rb") as f:
            d = json.loads(f.read().decode("utf-8", "replace"))
        if not isinstance(d, dict):
            return {"attempts": 0, "history": []}
        d.setdefault("attempts", 0)
        d.setdefault("history", [])
        return d
    except Exception:  # noqa: BLE001
        return {"attempts": 0, "history": []}


def _save_state(state: str, data: dict) -> dict:
    dest = os.path.abspath(state)
    parent = os.path.dirname(dest) or "."
    os.makedirs(parent, exist_ok=True)
    _textio.write_text(dest, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    return {"ok": True, "file": dest, "wrote_bom": _textio.has_bom(dest)}


def check(path: str, source: str = "", base: int = 0, target: str | int = 0,
          symbol: str = "", code: str = "", state: str = "",
          max_attempts: int = MAX_ATTEMPTS) -> dict:
    """候选 C 与镜像里这段机器码的结构体检。

    ``source`` 是候选 C 的**文件路径**，``code`` 是直接给源码文本（二选一）。
    ``state`` 给一个 JSON 路径时启用修错环计数：每调用一次 +1，超过
    ``max_attempts`` 直接拒绝（返回 ``ok:false`` + ``attempt_budget_exhausted``）。
    """
    path = str(path or "").strip()
    if not path:
        return {"ok": False, "error": "缺少 path"}
    if source:
        sp = str(source).strip()
        if not os.path.isfile(sp):
            return {"ok": False, "error": "候选源码文件不存在：%s" % sp,
                    "hint": "要么给存在的文件路径，要么用 code= 直接给源码文本"}
        with open(sp, "rb") as f:
            code = f.read().decode("utf-8", "replace")
        src_label = os.path.abspath(sp)
    else:
        if not str(code or "").strip():
            return {"ok": False,
                    "error": "没有候选源码：给 source（文件路径）或 code（源码文本）"}
        src_label = "inline"

    st = {"attempts": 0, "history": []}
    if state:
        st = _load_state(state)
        if int(st.get("attempts") or 0) >= int(max_attempts or MAX_ATTEMPTS):
            return {"ok": False, "error_code": "attempt_budget_exhausted",
                    "function": None,
                    "attempts": {"count": int(st.get("attempts") or 0),
                                 "max": int(max_attempts or MAX_ATTEMPTS),
                                 "state_file": os.path.abspath(state)},
                    "history": st.get("history") or [],
                    "error": "这个函数的修错轮次已经用满（%d/%d）：停下来换思路，"
                             "或者确认前几轮看到的问题到底是什么"
                             % (int(st.get("attempts") or 0),
                                int(max_attempts or MAX_ATTEMPTS)),
                    "hint": "要重开计数就把 state 文件删掉，或换一个新的 state 路径"}

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
    rf = _recover.recover_functions(unit, deep=True)
    funcs = rf.get("functions") or []
    f = None
    if addr:
        a = int(addr) & ~1
        f = next((x for x in funcs if int(x["addr"]) == a), None)
    elif symbol:
        f = next((x for x in funcs if str(x.get("name") or "") == str(symbol)), None)
    if f is None:
        return {"ok": False,
                "error": "找不到目标函数（给 target 地址或精确 symbol）",
                "function_count": len(funcs)}
    start = int(f["addr"])
    end = int(f.get("end_addr") or 0) or (start + max(int(f.get("size") or 0), 4))
    d = _recover.disassemble(unit, start, end)
    if not d.get("ok"):
        return {"ok": False, "verdict": "unknown",
                "error": "无法反汇编这个函数：%s" % (d.get("error") or ""),
                "hint": "没有汇编就没有结构比对，不猜"}

    src = _src_stats(code)
    asm = _asm_stats(d["insns"])
    sig = _signals(src, asm)
    if any(s["severity"] == "strong" for s in sig):
        verdict = "strong_mismatch"
    elif sig:
        verdict = "weak_mismatch"
    else:
        verdict = "no_obvious_mismatch"

    if state:
        st["attempts"] = int(st.get("attempts") or 0) + 1
        st.setdefault("history", []).append({
            "attempt": st["attempts"], "verdict": verdict,
            "signals": [s["signal"] for s in sig],
            "function": f.get("name"), "addr_hex": "0x%08X" % start,
        })
        st["max_attempts"] = int(max_attempts or MAX_ATTEMPTS)
        _save_state(state, st)

    return {
        "ok": True,
        "artifact_kind": "check",
        "evidence_only": True,
        "verdict": verdict,
        "function": {"addr": start, "addr_hex": "0x%08X" % start,
                     "end_hex": "0x%08X" % end, "name": f.get("name")},
        "source": {"label": src_label, "stats": src},
        "asm": {"n_insns": asm["n_insns"], "calls": asm["calls"],
                "branches": asm["branches"],
                "backward_branches": asm["backward_branches"],
                "fp": asm["fp"]},
        "signals": sig,
        "attempts": {"count": int(st.get("attempts") or 0),
                     "max": int(max_attempts or MAX_ATTEMPTS),
                     "state_file": os.path.abspath(state) if state else ""},
        "next_actions": (
            ["先按 signals 里的 strong 项逐条核对：漏了哪个调用、少写了哪个循环、"
             "是不是把浮点当整数了"]
            if verdict == "strong_mismatch" else
            (["weak 项不影响判定，但值得看一眼：多半是内联/展开造成的数差"]
             if verdict == "weak_mismatch" else
             ["结构上没抓到明显问题——可以去 recover_c_build 做回编译比对，"
              "那边比的是指令序列，比这里强"]),
        ),
        "scope": ("这是**结构体检**，不是等价性证明：没有强不匹配只说明「没抓到明显错误」，"
                  "不说明语义等价；正则级的源码统计会漏掉宏/模板/内联展开的东西"),
    }
