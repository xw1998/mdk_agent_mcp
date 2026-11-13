# -*- coding: utf-8 -*-
"""还原计划线（批次107）：先排出「按什么顺序还原哪些函数」，再跟踪「哪些做完了」。

为什么要单独一条计划线：做过整片固件还原的人都知道，真正难的**不是**单个函数写不出来，
而是「从哪个函数开始」。直接按地址顺序做，第一个函数就在调一个还没写的函数；按名字
字母序做，做的是随机顺序。正确的顺序是**依赖序**：叶子先做（它只调库函数与已知的
硬件寄存器），等它的调用者需要拿它当「已知」时才轮到调用者。这样每一步输出的 C 都能
直接编译，拼进去不破坏已有部分。

本模块只做两件事，都不调模型、不碰目标硬件、不改任何字节：

  * :func:`build`  —— 出**计划**：函数清单（带依赖序位置、难度分档、排除原因）、分批、
    以及身份指纹（镜像 sha256 + 工具版本 + 基址）。落盘是 ``plan.json``。
  * :func:`status` —— 读计划 + 结果目录，报**覆盖**：五态
    ``unattempted / attempted / accepted / failed / stale``。

为什么状态要分 ``stale``：镜像换了（重新编译、换了固件版本）之后，旧的结果文件还在那里，
文件名还是那个名字，看起来「做过了」。但函数体早就变了，那份 C 是**旧镜像**的证据。
``identity`` 里的 sha256 或工具版本一变，整条计划就标 stale —— 宁可让你重做一遍，
也不让你拿着一份看起来齐活、其实对不上号的清单去交差。

口径（与批次101/102/105/106 一致）：

  * 判词只基于镜像里读得到的字节与结构，不猜语义；
  * 依赖边只认**直接调用**（``bl target`` / 直接分支）且目标落在已知函数入口上。
    间接调用（``blx rN``）与库函数解析不出目标就不算边，如实计入 ``gaps``——
    「依赖到了看不见的东西」与「没有依赖」是两件事；
  * 环（递归/相互递归）不强行拉平：环里的函数标 ``cycle: true`` 并整体排在后面，
    不假装能拓扑排序；
  * 函数体积优先用符号表里的 size；size 缺失（ARM 库的 ``_printf_*`` 这类很常见）
    时用「下一个函数入口 − 本入口」的跨度兜底，并在 ``size_basis`` 里写明是哪种，
    不让一个估计值长得像实测值；
  * 排除了不等于不重要：每条被排除项都带 ``reason``。
"""
from __future__ import annotations

import fnmatch
import json
import os
import re

from . import evidence as _evidence
from . import recover as _recover
from . import textio as _textio

# 计划里最多列多少个函数（再多就不是「一份能执行的清单」，而是一份导出）
MAX_FUNCTIONS = 20000
# 默认分批大小：一次 8 个是一个 AI 会话能踏实做完的量级
DEFAULT_BATCH = 8
# 「啊这就是个常量返回」的体积上限（指令字节；Thumb 最短指令 2 字节）
TRIVIAL_BYTES = 8

ORDERS = ("dependency", "easiest-first", "high-impact")
STATES = ("unattempted", "attempted", "accepted", "failed", "stale")

# 结果文件里「算做出来了」的判词（来自 recover_c_check / recover_c_build）
ACCEPTED_VERDICTS = {
    "no_obvious_mismatch",   # 结构体检没抓到强不匹配
    "no_strong_mismatch",
    "exact_sequence",        # 回编译后规范化指令序列逐条相同
    "structural_match",      # 回编译后结构相同（常量/地址可能不同）
}
FAILED_VERDICTS = {
    "strong_mismatch",
    "weak_mismatch",         # 可疑但不硬：按「没通过」算，不按通过算
    "differs",
    "build_failed",
    "rejected",
}

_BAD_NAME = re.compile(r"[^0-9A-Za-z_.-]+")


# ----------------------------------------------------------------------
# 身份指纹
# ----------------------------------------------------------------------
def tool_version() -> str:
    try:
        from . import __version__
        return str(__version__)
    except Exception:  # noqa: BLE001
        return "unknown"


def identity_of(path: str, base: int = 0) -> dict:
    """镜像身份：sha256 + 体积 + 基址 + 工具版本。

    这四样任一变，之前的结果就不能再算数（基址变了意味着地址全挪了，
    名字对得上不代表函数对得上）。
    """
    data, err = _recover._read_file(path)
    if err:
        return err
    return {
        "ok": True,
        "path": os.path.abspath(path),
        "name": os.path.basename(path),
        "size": len(data),
        "sha256": _recover.sha256_bytes(data),
        "base": int(base or 0),
        "tool_version": tool_version(),
    }


# ----------------------------------------------------------------------
# 体积与依赖
# ----------------------------------------------------------------------
def _spans(funcs: list) -> dict:
    """``{addr: (span_bytes, basis)}``：体积优先看符号表，缺失用入口间距兜底。"""
    addrs = sorted(int(f["addr"]) for f in funcs)
    nxt = {}
    for i, a in enumerate(addrs):
        nxt[a] = addrs[i + 1] if i + 1 < len(addrs) else a
    out = {}
    for f in funcs:
        a = int(f["addr"])
        size = int(f.get("size") or 0)
        if size > 0:
            out[a] = (size, "symtab")
        else:
            gap = int(nxt.get(a, a)) - a
            out[a] = (max(0, gap), "gap" if gap > 0 else "unknown")
    return out


def _edges(funcs: list) -> tuple:
    """从函数清单里取直接调用边：``({addr: set(callee_addr)}, n_external)``。

    只认落在**已知函数入口**上的目标；指到别处的边不建，但要计数——
    那些依赖是看不见的，不是没有。
    """
    known = {int(f["addr"]) for f in funcs}
    out = {}
    external = 0
    for f in funcs:
        a = int(f["addr"])
        s = set()
        for t in (f.get("call_targets") or []):
            t = int(t or 0) & ~1
            if t in known:
                s.add(t)
            else:
                external += 1
        out[a] = s
    return out, external


def dependency_order(funcs: list, edges: dict) -> tuple:
    """post-order DFS：被调者先出现。返回 ``(order_addrs, cycles, n_cycle_funcs)``。

    迭代实现（固件里上千个函数，递归会撞 Python 递归深度）。遇到指向栈上节点的边
    就是找到了环：把该节点及其在栈上的后代标成 ``cycle``，它们**不打乱**别人的顺序，
    只是被排到所有无环函数之后——不假装把环拉平了。
    """
    order, state, cyc = [], {}, set()   # state: 0 未访问 / 1 在栈上 / 2 已完成
    for root in sorted(edges):
        if state.get(root, 0) != 0:
            continue
        state[root] = 1
        stack = [(root, iter(sorted(edges.get(root) or ())))]
        while stack:
            node, it = stack[-1]
            pushed = False
            for nxt in it:
                st = state.get(nxt, 0)
                if st == 0:
                    state[nxt] = 1
                    stack.append((nxt, iter(sorted(edges.get(nxt) or ()))))
                    pushed = True
                    break
                if st == 1:
                    idx = next((i for i, (a, _i) in enumerate(stack) if a == nxt),
                               len(stack))
                    for a, _i in stack[idx:]:
                        cyc.add(a)
                    cyc.add(nxt)
            if pushed:
                continue
            stack.pop()
            state[node] = 2
            if node not in cyc:
                order.append(node)
    tail = sorted(a for a in edges if a in cyc)   # 环里的统一补到末尾
    return order + tail, sorted(cyc), len(cyc)


def _difficulty(f: dict, span: int, basis: str) -> tuple:
    """难度分档：``(score, level, reasons[])``。只看能从镜像里读出来的结构量。"""
    score = 0
    why = ["%d 字节" % span if basis != "unknown" else "体积未知（符号表与入口间距都给不出）"]
    if basis == "gap":
        why.append("体积是**入口间距**兜底（符号表没给 size），可能偏大")
    if span > 600:
        score += 3
        why.append("很大")
    elif span > 240:
        score += 2
        why.append("偏大")
    elif span > 80:
        score += 1
        why.append("中等")
    n_cases = int(f.get("n_cases") or 0)
    if n_cases:
        why.append("跳转表 %d 个 case" % n_cases)
        if n_cases >= 6:
            score += 1
    callees = int(f.get("callee_count") or len(f.get("call_targets") or []))
    if callees >= 6:
        score += 1
        why.append("调用 %d 个函数" % callees)
    elif callees:
        why.append("调用 %d 个函数" % callees)
    level = "easy" if score <= 1 else ("medium" if score <= 3 else "hard")
    return score, level, why


def _excluded_reason(f: dict, span: int, basis: str, patterns: list) -> str:
    """这条函数该不该从「写 C 的对象」里排除，返回原因（空串=保留）。"""
    if f.get("is_thunk"):
        return ("thunk：函数体只有一条跳到别处（目标 %s），本身没有可写的东西"
                % (f.get("thunk_to_hex") or "未知"))
    if basis != "unknown" and 0 <= span <= TRIVIAL_BYTES and \
            not (f.get("call_targets") or []):
        return "常量返回/stub：体积 %d 字节且没有调用，几乎没有函数体" % span
    name = str(f.get("name") or "")
    for p in patterns:
        if fnmatch.fnmatchcase(name, p):
            return "名字匹配库函数排除规则 `%s`" % p
    return ""


def _kind_of(reason: str) -> str:
    if reason.startswith("thunk"):
        return "thunk"
    if reason.startswith("常量返回"):
        return "trivial"
    return "library"


# ----------------------------------------------------------------------
# build：出计划
# ----------------------------------------------------------------------
def build(path: str, base: int = 0, *, order: str = "dependency",
          batch: int = DEFAULT_BATCH, exclude: str = "thunk,trivial",
          library: str = "", limit: int = 0, out: str = "",
          deep: bool = True, max_functions: int = 0,
          max_insns: int = 0) -> dict:
    """出一份可执行的还原计划。

    ``order``：``dependency``（被调者先做，默认）/ ``easiest-first`` / ``high-impact``。
    ``batch``：分批大小（0=不分批）。``exclude``：默认排除 ``thunk,trivial``；
    给 ``none`` 表示一个都不排除。``library``：逗号分隔的名字通配（如
    ``memcpy*,__aeabi_*``）——**只按名字，不按指纹**，所以默认不启用。
    """
    path = str(path or "").strip()
    if not path:
        return {"ok": False, "error": "缺少 path"}
    order = str(order or "dependency").strip().lower()
    if order not in ORDERS:
        return {"ok": False,
                "error": "order 只能是 %s，收到 %r" % (" / ".join(ORDERS), order)}
    ex_kinds = [x.strip().lower() for x in str(exclude or "").split(",") if x.strip()]
    if "none" in ex_kinds:
        ex_kinds = []
    unknown = [x for x in ex_kinds if x not in ("thunk", "trivial")]
    if unknown:
        return {"ok": False,
                "error": "exclude 里有不认识的类别：%s（只支持 thunk / trivial / none）"
                         % ", ".join(unknown)}
    pats = [x.strip() for x in str(library or "").split(",") if x.strip()]

    an = _recover.analyze(path, base=int(base or 0), deep=bool(deep),
                          max_functions=int(max_functions or MAX_FUNCTIONS),
                          max_insns=int(max_insns or _recover.MAX_INSNS))
    unit = an.get("_unit")
    an.pop("_unit", None)
    an.pop("_recover", None)
    if not an.get("ok"):
        return an
    if unit is None:
        return {"ok": False, "error": "内部错误：剖析没有给出可寻址的镜像"}

    r = _recover.recover_functions(unit, deep=True,
                                   max_functions=int(max_functions or MAX_FUNCTIONS),
                                   max_insns=int(max_insns or _recover.MAX_INSNS))
    if not r.get("ok"):
        return r
    funcs = r.get("functions") or []
    gaps = [{"reason": str(g.get("reason") or "")}
            for g in (r.get("gaps") or []) if isinstance(g, dict)]

    spans = _spans(funcs)
    edges, n_external = _edges(funcs)
    order_addrs, cycles, n_cycle = dependency_order(funcs, edges)
    pos = {a: i for i, a in enumerate(order_addrs)}
    cyc_set = set(cycles)
    if n_cycle:
        gaps.append({"reason": "有 %d 个函数处在调用环里（递归/相互递归），"
                               "它们排在无环函数之后，依赖序在环内不成立" % n_cycle})
    if n_external:
        gaps.append({"reason": "有 %d 条调用目标不落在任何已识别函数入口上"
                               "（库函数、未识别代码或间接调用解不出来的目标）——"
                               "这些依赖**没有**被当成边，所以依赖序可能不完整" % n_external})

    rows, excluded = [], []
    for f in funcs:
        a = int(f["addr"])
        span, basis = spans[a]
        score, level, why = _difficulty(f, span, basis)
        reason = _excluded_reason(f, span, basis, pats)
        if reason and _kind_of(reason) in ex_kinds:
            excluded.append({"addr": a, "addr_hex": f.get("addr_hex"),
                             "name": f.get("name"), "kind": _kind_of(reason),
                             "reason": reason})
            continue
        if reason:
            why = why + [reason + "（该类已由 exclude 关掉，本项仍列出）"]
        rows.append({
            "addr": a,
            "addr_hex": f.get("addr_hex"),
            "name": f.get("name") or ("sub_%08X" % a),
            "size_bytes": span,
            "size_basis": basis,
            "n_callers": int(f.get("n_callers") or 0),
            "n_callees": int(f.get("callee_count") or 0),
            "n_cases": int(f.get("n_cases") or 0),
            "confidence": f.get("confidence"),
            "depends_on": ["0x%08X" % t for t in sorted(edges.get(a) or ())],
            "cycle": a in cyc_set,
            "difficulty": level,
            "difficulty_score": score,
            "difficulty_reasons": why,
        })

    if order == "dependency":
        rows.sort(key=lambda x: (x["cycle"], pos.get(x["addr"], 10 ** 9)))
    elif order == "easiest-first":
        rows.sort(key=lambda x: (x["difficulty_score"], x["size_bytes"], x["addr"]))
    else:  # high-impact
        rows.sort(key=lambda x: (-x["n_callers"], -x["size_bytes"], x["addr"]))

    total = len(rows)
    if limit and int(limit) > 0:
        rows = rows[:int(limit)]
    n_batch = int(batch or 0)
    for i, row in enumerate(rows):
        row["index"] = i
        row["batch"] = (i // n_batch + 1) if n_batch > 0 else 0

    batches = []
    if n_batch > 0:
        for i in range(0, len(rows), n_batch):
            chunk = rows[i:i + n_batch]
            batches.append({"batch": i // n_batch + 1,
                            "size": len(chunk),
                            "start_index": i,
                            "end_index": i + len(chunk) - 1,
                            "functions": ["0x%08X" % c["addr"] for c in chunk]})

    out_d = {
        "ok": True,
        "artifact_kind": "plan",
        "evidence_only": True,
        "identity": {"path": an.get("path"), "name": os.path.basename(path),
                     "size": an.get("size"), "sha256": an.get("sha256"),
                     "base": int(base or 0), "tool_version": tool_version(),
                     "container": an.get("container")},
        "order": order,
        "batch_size": n_batch,
        "counts": {
            "in_image": len(funcs),
            "planned": total,
            "listed": len(rows),
            "excluded": len(excluded),
            "batches": len(batches),
            "cycle": n_cycle,
            "easy": sum(1 for x in rows if x["difficulty"] == "easy"),
            "medium": sum(1 for x in rows if x["difficulty"] == "medium"),
            "hard": sum(1 for x in rows if x["difficulty"] == "hard"),
        },
        "functions": rows,
        "batches": batches,
        "excluded": excluded,
        "gaps": gaps,
        "how_to": [
            "按 functions 的顺序（dependency 序）逐个做；batches 就是一轮一轮的分组",
            "轮到某个函数时先取证据包 recover_c_context，再写 C（由宿主 AI 写），"
            "写完用 recover_c_check 做结构体检，最后用 recover_c_build 回编译比对",
            "结果文件放到同一个 results 目录，recover_status 会按身份指纹判定是否过期",
        ],
    }
    if out:
        w = _write_plan(out_d, out)
        out_d["out"] = w
        if not w.get("ok"):
            out_d["ok"] = False
            out_d["error"] = w.get("error")
    return out_d


def _safe_stem(text: str, fallback: str = "plan") -> str:
    s = _BAD_NAME.sub("_", str(text or "")).strip("._-")
    return s or fallback


def _write_json_artifact(payload: dict, out: str, default_name: str) -> dict:
    """落一份 JSON 证据（utf-8 无 BOM）。``out`` 可以是目录或直接是 .json 文件。"""
    dest = os.path.abspath(out)
    if dest.lower().endswith(".json"):
        parent = os.path.dirname(dest) or "."
        bad = _evidence.violation(parent)
        if bad:
            return {**_evidence.refusal(parent, bad), "out_dir": parent}
        os.makedirs(parent, exist_ok=True)
        target = dest
    else:
        bad = _evidence.violation(dest)
        if bad:
            return {**_evidence.refusal(dest, bad), "out_dir": dest}
        os.makedirs(dest, exist_ok=True)
        target = os.path.join(dest, default_name)
    _textio.write_text(target, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    return {"ok": True, "file": target, "out_dir": os.path.dirname(target),
            "evidence_only": True, "wrote_bom": _textio.has_bom(target)}


def _write_plan(plan: dict, out: str) -> dict:
    return _write_json_artifact(plan, out, "plan.json")


# ----------------------------------------------------------------------
# status：五态覆盖
# ----------------------------------------------------------------------
_SUFFIXES = (".check.json", ".build.json", ".result.json", ".json", ".c", ".md")


def _stem_of(filename: str) -> str:
    s = os.path.basename(filename)
    for suf in _SUFFIXES:
        if s.lower().endswith(suf):
            return s[:-len(suf)]
    return os.path.splitext(s)[0]


def _keys_of(row: dict) -> list:
    keys = []
    ah = str(row.get("addr_hex") or "").lower()
    if ah.startswith("0x"):
        keys.append(ah)
        keys.append(ah[2:])
    name = _safe_stem(str(row.get("name") or ""), "").lower()
    if name:
        keys.append(name)
    return keys


def _scan(results_dir: str) -> dict:
    """扫结果目录：``{stem_lower: [相对路径...]}``（递归，允许一层层分子目录）。"""
    idx = {}
    if not results_dir or not os.path.isdir(results_dir):
        return idx
    for root, _dirs, files in os.walk(results_dir):
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, results_dir)
            stem = _stem_of(fn).lower()
            idx.setdefault(stem, []).append(rel)
            if "__" in stem:      # `<addr_hex>__<name>.c` 两个键都认
                for part in stem.split("__"):
                    if part:
                        idx.setdefault(part, []).append(rel)
    return idx


def _verdict_from(files: list, results_dir: str) -> tuple:
    """从结果 JSON 里取判词：``(verdict, "kind:file")``。优先级 build > check > 其它。"""
    rank = {"build": 3, "check": 2, "result": 1}
    best_v, best_src, best_rank = "", "", 0
    for rel in files:
        low = rel.lower()
        if not low.endswith(".json"):
            continue
        kind = ("build" if low.endswith(".build.json")
                else "check" if low.endswith(".check.json") else "result")
        if rank.get(kind, 0) < best_rank:
            continue
        try:
            with open(os.path.join(results_dir, rel), "rb") as f:
                d = json.loads(f.read().decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            continue
        v = str((d or {}).get("verdict") or "").strip().lower()
        if v:
            best_v, best_src, best_rank = v, "%s:%s" % (kind, rel), rank.get(kind, 0)
    return best_v, best_src


def status(plan_path: str, results_dir: str = "", *, out: str = "",
           current: str = "", base: int = 0) -> dict:
    """读计划 + 结果目录，报五态覆盖与是否 stale。

    ``current`` 可指定**当前**镜像（默认用计划里记的路径）：它的 sha256 与计划里不同，
    或工具版本变了，整条计划标 ``stale``，所有条目一律按 stale 报。
    """
    plan_path = str(plan_path or "").strip()
    if not plan_path or not os.path.isfile(plan_path):
        return {"ok": False, "error": "计划文件不存在：%s" % plan_path}
    try:
        with open(plan_path, "rb") as f:
            plan = json.loads(f.read().decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "计划文件不是可解析的 JSON：%s" % e}
    if not isinstance(plan, dict) or not plan.get("functions"):
        return {"ok": False,
                "error": "这不是 recover_plan 出来的计划（没有 functions 清单）",
                "hint": "先跑 recover_plan(out=...) 生成 plan.json"}
    ident = plan.get("identity") or {}
    cur = {"path": ident.get("path"), "sha256": ident.get("sha256"),
           "base": int(ident.get("base") or 0), "tool_version": tool_version()}
    reasons = []
    if current:
        now = identity_of(current, base=int(base or 0))
        if not now.get("ok"):
            return now
        cur.update({"path": now["path"], "sha256": now["sha256"],
                    "base": now["base"], "size": now["size"]})
        if now["sha256"] != ident.get("sha256"):
            reasons.append("镜像变了：计划里 %s，现在 %s"
                           % (str(ident.get("sha256"))[:12], now["sha256"][:12]))
        if int(now["base"] or 0) != int(ident.get("base") or 0):
            reasons.append("基址变了：计划里 0x%08X，现在 0x%08X"
                           % (int(ident.get("base") or 0), int(now["base"] or 0)))
    if cur["tool_version"] != ident.get("tool_version"):
        reasons.append("工具版本变了：计划里 %s，现在 %s"
                       % (ident.get("tool_version"), cur["tool_version"]))
    if not reasons and ident.get("path") and os.path.isfile(ident["path"]):
        now = identity_of(ident["path"], base=int(ident.get("base") or 0))
        if now.get("ok") and now["sha256"] != ident.get("sha256"):
            reasons.append("镜像变了：计划里 %s，现在 %s"
                           % (str(ident.get("sha256"))[:12], now["sha256"][:12]))

    rdir = str(results_dir or "").strip()
    files = _scan(rdir)
    rows = []
    counts = {k: 0 for k in STATES}
    for row in plan["functions"]:
        hit = []
        for k in _keys_of(row):
            hit.extend(files.get(k) or [])
        hit = sorted(set(hit))
        verdict, src = _verdict_from(hit, rdir) if rdir else ("", "")
        has_c = any(x.lower().endswith(".c") for x in hit)
        if reasons:
            state = "stale"
        elif verdict in ACCEPTED_VERDICTS:
            state = "accepted"
        elif verdict in FAILED_VERDICTS:
            state = "failed"
        elif has_c:
            state = "attempted"
        else:
            state = "unattempted"
        counts[state] += 1
        rows.append({"index": row.get("index"), "addr": row.get("addr"),
                     "addr_hex": row.get("addr_hex"), "name": row.get("name"),
                     "batch": row.get("batch"), "difficulty": row.get("difficulty"),
                     "state": state, "verdict": verdict or None,
                     "verdict_from": src or None, "files": hit,
                     "has_c": bool(has_c)})
    planned = len(rows)
    touched = counts["attempted"] + counts["accepted"] + counts["failed"]
    out_d = {
        "ok": True,
        "artifact_kind": "status",
        "evidence_only": True,
        "plan_file": os.path.abspath(plan_path),
        "results_dir": os.path.abspath(rdir) if rdir else "",
        "identity": {"planned": ident, "current": cur},
        "stale": bool(reasons),
        "stale_reasons": reasons,
        "counts": counts,
        "planned": planned,
        "coverage": {
            "attempted_ratio": round((touched + counts["stale"]) / planned, 4) if planned else 0.0,
            "accepted_ratio": round(counts["accepted"] / planned, 4) if planned else 0.0,
        },
        "functions": rows,
        "scope": ("覆盖只描述**这份计划里的函数**，不代表整个程序；状态来自结果目录里的"
                  "文件与判词，不证明语义等价"),
    }
    if out:
        w = _write_json_artifact(out_d, out, "status.json")
        out_d["out"] = w
        if not w.get("ok"):
            out_d["ok"] = False
            out_d["error"] = w.get("error")
    return out_d
