# -*- coding: utf-8 -*-
"""候选 C 回编译比对（批次107）——把「写得像」变成「编出来是不是同一段机器码」。

这是本仓库在还原 C 这件事上**唯一别人（纯分析型工具）给不出**的能力：手上就有
原来的 ARM 工具链（AC5 ``armcc`` / AC6 ``armclang``），所以候选 C 可以真的编成
目标文件，再和目标函数在镜像里的指令序列做结构比对。

比对是**结构级**的，不是逐字节：

  * ``exact_sequence``    —— 规范化后的指令序列逐条相同（立即数/地址已抹平）；
  * ``structural_match``  —— 助记符多重集相同，或相似度 ≥ threshold 且调用数相同、
                              分支数差 ≤ 1、栈帧 push 数相同；
  * ``differs``           —— 编出来了，但序列实质不同（附第一条分歧与差异摘要）；
  * ``build_failed``      —— 编译没通过（附编译器原始错误）。

**结构相同不等于语义等价**：寄存器分配、指令选择、常量强度折减都会让源代码写法不同
却编出同一段码；反过来同一段码也可能来自不同的合法源码。这里判的是「像不像同一段
机器码」，不是「这段 C 是不是原始源码」。判词里一律带这句。

REL 目标文件没有绝对地址（``.o`` 里每个函数在自己的 ``.text.<name>`` 节，符号值是节内
偏移），所以不能拿 ``recover_functions`` 那套走：本模块**直接按节取字节**，再用
``Unit`` 包成一段可反汇编的原始码（架构沿用原镜像），比对时把地址类操作数抹平。
"""
from __future__ import annotations

import difflib
import os
import re
import shutil
import subprocess
import tempfile

from . import recover as _recover

MAX_STDERR = 4000
# 临时目录里编译器产物的名字（固定，便于排查；work_dir 由调用方决定保留与否）
SRC_NAME = "candidate.c"
OBJ_NAME = "candidate.o"

# 比对时抹平的写法：立即数、地址、跳转目标
_IMM_RE = re.compile(r"#?\s*-?0x[0-9A-Fa-f]+")
_DEC_RE = re.compile(r"(?<![\w.])-?\d+(?![\w.])")


def _default_cpu(unit) -> str:
    """架构 → 编译用的 -mcpu。判不出来就给 cortex-m4 并**在输出里写明是默认值**。"""
    arch = unit.arch or {}
    if arch.get("family") == "arm" and arch.get("thumb"):
        return "cortex-m4"
    return "cortex-m4"


def find_compilers(explicit_dir: str = "") -> dict:
    """定位 AC5 ``armcc`` 与 AC6 ``armclang``。找不到就如实说找不到。"""
    ac5, ac6 = "", ""
    tried = []
    dirs = []
    if explicit_dir:
        dirs.append(explicit_dir)
    env = os.environ.get("MDK_ARMCC_BIN") or ""
    if env:
        dirs.append(env)
    try:
        f = _recover.find_arm_tools()
        if f.get("ok"):
            d = f["bin_dir"]
            dirs.append(d)
            # <root>\ARM\ARMCC\bin → <root>\ARM\ARMCLANG\bin
            parent = os.path.dirname(os.path.dirname(d))
            dirs.append(os.path.join(parent, "ARMCLANG", "bin"))
        tried.extend(f.get("tried") or [])
    except Exception as e:  # noqa: BLE001
        tried.append("find_arm_tools 失败：%s" % e)
    for d in dirs:
        if not d:
            continue
        tried.append(d)
        for name, ext in (("armcc", ".exe" if os.name == "nt" else ""),
                          ("armclang", ".exe" if os.name == "nt" else "")):
            p = os.path.join(d, name + ext)
            if not os.path.isfile(p):
                continue
            if name == "armcc" and not ac5:
                ac5 = p
            if name == "armclang" and not ac6:
                ac6 = p
    if not ac6:
        w = shutil.which("armclang")
        if w:
            ac6 = w
    if not ac5:
        w = shutil.which("armcc")
        if w:
            ac5 = w
    return {"ok": bool(ac5 or ac6), "ac5": ac5, "ac6": ac6,
            "tried": sorted(set(tried))[:20],
            "error": "" if (ac5 or ac6) else
                     "找不到 ARM 编译器（armcc / armclang）",
            "hint": "装 Keil MDK，或设 MDK_ARMCC_BIN=<...\\ARM\\ARMCC\\bin>"}


def _compile(compiler: str, work_dir: str, *, cpu: str, opt: str,
             includes: list, ac6: bool) -> dict:
    src = os.path.join(work_dir, SRC_NAME)
    obj = os.path.join(work_dir, OBJ_NAME)
    if ac6:
        cmd = [compiler, "--target=arm-arm-none-eabi", "-mcpu=%s" % cpu, "-mthumb",
               "-ffunction-sections", "-fdata-sections", str(opt or "-O2"),
               "-c", src, "-o", obj]
    else:
        cmd = [compiler, "--cpu", cpu[0].upper() + cpu[1:] if cpu else "Cortex-M4",
               "--thumb", "--c99", "--apcs=interwork", str(opt or "-O2"),
               "-c", src, "-o", obj]
    for inc in includes:
        cmd.insert(-2, "-I%s" % inc)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=180, cwd=work_dir)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "调用编译器失败：%s" % e, "cmd": cmd}
    text = ((p.stdout or "") + (p.stderr or "")).strip()
    if p.returncode != 0 or not os.path.isfile(obj):
        return {"ok": False, "returncode": p.returncode, "cmd": cmd,
                "error": "编译失败", "stderr": text[:MAX_STDERR]}
    return {"ok": True, "cmd": cmd, "obj": obj, "stdout": text[:MAX_STDERR]}


def _elf_text_sections(obj: str) -> dict:
    """读 ``.o``：返回 ``{sec_name: {"data": bytes, "funcs": [{name,value,size}]}}``。

    REL 里没有绝对地址，函数靠符号的 ``st_value``（节内偏移）定位。
    """
    from elftools.elf.elffile import ELFFile          # noqa: PLC0415
    out = {}
    with open(obj, "rb") as f:
        e = ELFFile(f)
        symtab = e.get_section_by_name(".symtab")
        per_sec = {}
        if symtab is not None:
            for sym in symtab.iter_symbols():
                if sym["st_info"]["type"] != "STT_FUNC":
                    continue
                if not sym["st_size"] and not sym["st_value"]:
                    continue
                sec = e.get_section(sym["st_shndx"]) if sym["st_shndx"] else None
                name = sec.name if sec is not None else ""
                per_sec.setdefault(name, []).append({
                    "name": sym.name, "value": int(sym["st_value"]),
                    "size": int(sym["st_size"]),
                })
        for sec in e.iter_sections():
            if not sec.name.startswith(".text"):
                continue
            data = sec.data() if sec["sh_type"] != "SHT_NOBITS" else b""
            if not data:
                continue
            out[sec.name] = {"data": data,
                             "funcs": per_sec.get(sec.name, [])}
    return out


def _disasm_blob(blob: bytes, arch: dict, *, start_off: int = 0,
                 length: int = 0) -> dict:
    """把一段裸字节包成可反汇编的 Unit（架构沿用原镜像）。"""
    base = 0x01000000            # 只为了让反汇编输出可读；地址一律会被抹平
    u = _recover.Unit(blob, "<object>", base=base, infer_base=False)
    u.arch = dict(arch or {})
    u.limitations = list(getattr(u, "limitations", []) or [])
    n = length or len(blob)
    r = _recover.disassemble(u, base + start_off, base + start_off + n)
    return r


def _norm_seq(rows: list) -> list:
    """规范化：助记符 + 抹平立即数/地址后的操作数。"""
    out = []
    for r in rows:
        op = str(r.get("op_str") or "")
        op = _IMM_RE.sub("<IMM>", op)
        op = _DEC_RE.sub("<IMM>", op)
        op = re.sub(r"\s+", " ", op).strip()
        out.append(("%s %s" % ((r.get("mnemonic") or "").lower(), op)).strip())
    return out


def _mnemonic_counts(rows: list) -> dict:
    c = {}
    for r in rows:
        m = (r.get("mnemonic") or "").lower()
        c[m] = c.get(m, 0) + 1
    return c


def _calls(rows: list) -> int:
    return sum(1 for r in rows if (r.get("mnemonic") or "").lower() in ("bl", "blx"))


def _branches(rows: list) -> int:
    n = 0
    for r in rows:
        m = (r.get("mnemonic") or "").lower()
        if m.startswith("b") and m not in ("bl", "blx", "bic", "bics", "bfi", "bfc",
                                           "bkpt", "bx"):
            n += 1
    return n


def _pushes(rows: list) -> int:
    """栈帧 push 的寄存器数（prologue 成本的最直观指标）。"""
    n = 0
    for r in rows:
        if (r.get("mnemonic") or "").lower() == "push":
            op = str(r.get("op_str") or "")
            inside = op[op.find("{") + 1:op.find("}")] if "{" in op else op
            n += len([x for x in inside.split(",") if x.strip()])
    return n


def build(path: str, source: str = "", base: int = 0, target: str | int = 0,
          symbol: str = "", code: str = "", compiler: str = "auto",
          cpu: str = "", opt: str = "-O2", includes: str = "",
          work_dir: str = "", keep: bool = False,
          threshold: float = 0.8) -> dict:
    """把候选 C 编出来，与镜像里目标函数的指令序列做结构比对。

    ``source``：候选 C 文件路径；``code``：直接给源码文本。``compiler``：
    ``auto``（优先 AC6）/ ``ac5`` / ``ac6``。``work_dir`` 给了就用它（``keep=False``
    时结束后清理其中本模块的产物）。
    """
    path = str(path or "").strip()
    if not path:
        return {"ok": False, "error": "缺少 path"}
    if source and os.path.isfile(str(source)):
        with open(str(source), "rb") as f:
            code = f.read().decode("utf-8", "replace")
        src_label = os.path.abspath(str(source))
    elif str(code or "").strip():
        src_label = "inline"
    else:
        return {"ok": False,
                "error": "没有候选源码：给 source（存在的 .c 文件）或 code（源码文本）"}
    if b"\x00" in code.encode("utf-8", "replace"):
        return {"ok": False, "error": "源码里有 NUL 字节：不是文本文件"}

    try:
        addr = int(str(target).strip(), 0) if isinstance(target, str) else int(target or 0)
    except ValueError:
        return {"ok": False, "error": "target 必须是地址，收到 %r" % target}

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
    orig = _recover.disassemble(unit, start, end)
    if not orig.get("ok"):
        return {"ok": False, "verdict": "unknown",
                "error": "无法反汇编目标函数：%s" % (orig.get("error") or "")}

    tc = find_compilers()
    want = str(compiler or "auto").strip().lower()
    use_ac6 = (want == "ac6") or (want == "auto" and bool(tc["ac6"]))
    exe = tc["ac6"] if use_ac6 else tc["ac5"]
    if want == "ac5":
        exe, use_ac6 = tc["ac5"], False
    if not exe:
        return {"ok": False, "error_code": "toolchain_not_found",
                "verdict": "build_failed",
                "error": tc["error"], "hint": tc["hint"], "tried": tc["tried"],
                "tool": "ac6" if use_ac6 else "ac5"}

    own_dir = not work_dir
    wd = os.path.abspath(work_dir) if work_dir else tempfile.mkdtemp(prefix="mdk107_")
    os.makedirs(wd, exist_ok=True)
    src_file = os.path.join(wd, SRC_NAME)
    try:
        with open(src_file, "wb") as fh:
            fh.write(code.encode("utf-8"))
        incs = [x.strip() for x in str(includes or "").split(",") if x.strip()]
        cp = _compile(exe, wd, cpu=str(cpu or _default_cpu(unit)),
                      opt=str(opt or "-O2"), includes=incs, ac6=use_ac6)
        if not cp.get("ok"):
            return {"ok": True, "verdict": "build_failed",
                    "error": cp.get("error"), "returncode": cp.get("returncode"),
                    "stderr": cp.get("stderr") or "",
                    "cmd": [os.path.basename(x) for x in (cp.get("cmd") or [])],
                    "tool": "ac6" if use_ac6 else "ac5",
                    "source": src_label,
                    "next_actions": ["按 stderr 修到能编过（类型/原型/头文件），"
                                     "再回来看结构比对"]}
        secs = _elf_text_sections(cp["obj"])
        if not secs:
            return {"ok": True, "verdict": "build_failed",
                    "error": "编译成功但没有 .text 内容（源码里没有函数定义？）",
                    "source": src_label}
        # 选要比的节：优先符号名与目标函数同名，否则取最大的那个
        target_name = str(f.get("name") or "")
        chosen, chosen_sym = "", None
        for name, sec in secs.items():
            for fn in sec["funcs"]:
                if target_name and fn["name"] == target_name:
                    chosen, chosen_sym = name, fn
                    break
            if chosen:
                break
        if not chosen:
            chosen = max(secs, key=lambda k: len(secs[k]["data"]))
            syms = secs[chosen]["funcs"]
            chosen_sym = max(syms, key=lambda s: s["size"]) if syms else None
        blob = secs[chosen]["data"]
        off = int((chosen_sym or {}).get("value") or 0) & ~1
        length = int((chosen_sym or {}).get("size") or 0) or (len(blob) - off)
        if off >= len(blob):
            return {"ok": True, "verdict": "build_failed",
                    "error": "符号偏移超出节大小（%d >= %d）" % (off, len(blob))}
        cand = _disasm_blob(blob, unit.arch, start_off=off, length=length)
        if not cand.get("ok"):
            return {"ok": True, "verdict": "build_failed",
                    "error": "候选目标码反汇编失败：%s" % (cand.get("error") or "")}
    finally:
        if not keep:
            for n in (SRC_NAME, OBJ_NAME, "candidate.d", OBJ_NAME.replace(".o", ".d")):
                p = os.path.join(wd, n)
                try:
                    if os.path.isfile(p):
                        os.remove(p)
                except OSError:
                    pass
            if own_dir:
                try:
                    os.rmdir(wd)
                except OSError:
                    pass

    a = _norm_seq(orig["insns"])
    b = _norm_seq(cand["insns"])
    same = a == b
    ca, cb = _mnemonic_counts(orig["insns"]), _mnemonic_counts(cand["insns"])
    ratio = difflib.SequenceMatcher(None, [x.split()[0] for x in a],
                                    [x.split()[0] for x in b]).ratio()
    calls_a, calls_b = _calls(orig["insns"]), _calls(cand["insns"])
    br_a, br_b = _branches(orig["insns"]), _branches(cand["insns"])
    push_a, push_b = _pushes(orig["insns"]), _pushes(cand["insns"])

    if same:
        verdict = "exact_sequence"
    elif (ca == cb or (ratio >= float(threshold or 0.8)
                       and calls_a == calls_b
                       and abs(br_a - br_b) <= 1
                       and push_a == push_b)):
        verdict = "structural_match"
    else:
        verdict = "differs"

    first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y),
                 min(len(a), len(b)) if len(a) != len(b) else -1)
    img_lines = ["%08X %s" % (int(r["addr"]), x) for r, x in zip(orig["insns"], a)]
    # 候选的地址是合成基址（0x01000000），映射回原函数地址再比，否则两边地址没有可比性
    cand_lines = ["%08X %s" % (int(r["addr"]) - 0x01000000 + start, x)
                  for r, x in zip(cand["insns"], b)]
    diff_lines = list(difflib.unified_diff(img_lines, cand_lines,
                                           fromfile="image", tofile="candidate",
                                           n=2, lineterm=""))[:200]

    return {
        "ok": True,
        "artifact_kind": "build",
        "evidence_only": True,
        "verdict": verdict,
        "function": {"addr": start, "addr_hex": "0x%08X" % start,
                     "end_hex": "0x%08X" % end, "name": f.get("name")},
        "source": src_label,
        "tool": {"compiler": "ac6" if use_ac6 else "ac5",
                 "exe": os.path.basename(exe), "cpu": str(cpu or _default_cpu(unit)),
                 "cpu_is_default": not bool(cpu), "opt": str(opt or "-O2"),
                 "built_section": chosen,
                 "built_symbol": (chosen_sym or {}).get("name")},
        "compare": {
            "n_insns_image": len(orig["insns"]),
            "n_insns_candidate": len(cand["insns"]),
            "calls": [calls_a, calls_b],
            "branches": [br_a, br_b],
            "pushes": [push_a, push_b],
            "mnemonic_ratio": round(ratio, 4),
            "mnemonic_sets_equal": ca == cb,
            "first_diff_index": first,
            "first_diff": ({"image": a[first] if 0 <= first < len(a) else "",
                            "candidate": b[first] if 0 <= first < len(b) else ""}
                           if first >= 0 else None),
        },
        "diff": diff_lines,
        "scope": ("结构比对不是等价性证明：寄存器分配/指令选择会让不同源码编出同一段码，"
                  "同一段码也可能来自不同的合法源码。exact_sequence 只说明这版编译参数下"
                  "指令序列一致；换个 -O 档可能就变了"),
        "next_actions": (
            ["逐条看 diff：第一个分歧点通常在 prologue 或第一个调用点上"]
            if verdict == "differs" else
            ["结构对上了——可以再试 -O0/-O1/-Os 看是否更接近原厂编译参数，"
             "或换 AC5/AC6 复核"] if verdict == "structural_match" else
            ["指令序列一致：把这份 C 存进 results 目录，recover_status 会记成 accepted"]
        ),
    }
