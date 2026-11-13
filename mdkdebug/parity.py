# -*- coding: utf-8 -*-
"""行为 parity：把候选 C 编成真机器码，和原函数跑同一组输入，比可观测结果（批次108）。

批次107 的两条腿在这里接上：

* ``recover_c_build`` 证明「候选编出来的指令序列像不像」——**结构**像；
* ``recover_emulate`` 能在模拟器里跑一段机器码——**行为**看得见。

但它们之间缺一步：候选 C 编出来的是**可重定位的 .o**，里面没有绝对地址，跑不起来。
这一层补的就是这一步：拿原镜像的符号表生成 symdefs，让 armlink 把候选按
``--ro-base`` 链到一块空闲地址上（对原镜像外部函数的调用会解析成真地址），
于是候选和原函数处在同一个地址空间里，能用同一组寄存器/内存跑，逐项对比。

四条边界，写在最前面：

1. **一组输入就是一组输入**。``parity_exact`` 只说明「在这组参数下返回值与写内存
   逐字节一致」，不说明「两个函数等价」。要更强的结论得扫参数（调用方的事）。
2. **外设不建模**。任一侧碰到 0x40000000–0x5FFFFFFF 就停下并判 ``not_comparable``
   ——「停下那一刻寄存器恰好相等」不是 parity。
3. **全局变量地址不同**。候选的 RW 段落在自己的 ``--rw-base`` 上，原函数的全局变量
   在镜像的 RAM 里，所以**同一个全局变量在两侧的地址不同**。写内存比对按
   「地址 + 宽度」对齐，只在共同地址上比值——地址不同的写会被如实分到
   ``writes_only_in_*`` 两栏，不会被当成不一致。
4. **依赖可选**。unicorn 与 ARM 工具链任一缺失就 ``supported: false`` 并说清缺什么，
   **不降级成静态猜测**。
"""
from __future__ import annotations

import os
import shutil
import tempfile

from . import cbuild as CB
from . import emulate as EM
from . import plan as _plan
from . import recover as _recover

SRC_NAME = CB.SRC_NAME
OBJ_NAME = CB.OBJ_NAME
LINK_NAME = "cand.axf"
SYM_NAME = "symdefs.txt"

MAX_STDERR = 4000
DEFAULT_RO_BASE = 0
# 候选的 RW 段默认落在 RAM 区之外（模拟器给原镜像的 RAM 预留 0x10000）
DEFAULT_RW_SHIFT = 0x10000
ALIGN = 0x1000


def available() -> dict:
    """unicorn + ARM 工具链 + armlink 都在不在。"""
    emu = EM.available()
    tc = CB.find_compilers()
    linker = _find_linker(tc)
    missing = []
    if not emu.get("supported"):
        missing.append({"what": "unicorn", "hint": EM.INSTALL_HINT})
    if not (tc.get("ac5") or tc.get("ac6")):
        missing.append({"what": "armcc/armclang", "hint": tc.get("hint") or ""})
    if not linker:
        missing.append({"what": "armlink", "hint": "armlink 与 armcc 同在 <MDK>\\ARM\\ARMCC\\bin"})
    return {
        "supported": not missing,
        "unicorn": emu.get("supported") and emu.get("version") or "",
        "compiler": tc.get("ac5") or tc.get("ac6") or "",
        "linker": linker,
        "missing": missing,
        "why": "" if not missing else
               "缺 %s：先补齐再跑 parity（本工具不拿静态相似度冒充行为一致）"
               % "、".join(m["what"] for m in missing),
    }


def _find_linker(tc: dict) -> str:
    """armlink 与 armcc 同目录；也允许 shutil.which 或 MDK_ARMCC_BIN 指到。"""
    dirs = []
    for key in ("ac5", "ac6"):
        p = tc.get(key) or ""
        if p:
            dirs.append(os.path.dirname(p))
    env = os.environ.get("MDK_ARMCC_BIN") or ""
    if env:
        dirs.append(env)
    for d in dirs:
        for name in ("armlink", "armlink.exe"):
            cand = os.path.join(d, name)
            if os.path.isfile(cand):
                return cand
    w = shutil.which("armlink")
    return w or ""


def _symdefs_text(path: str) -> dict:
    """从原镜像的符号表生成 armlink 的 symdefs。

    只在镜像确实是带符号的 ELF 时可行；裸 .bin 没有符号表，候选里对原镜像函数的
    调用就解析不了——那种情况如实报 ``no_symdefs``，并在结果里写清后果。
    """
    data, err = _recover._read_file(path)
    if err:
        return err
    if not data.startswith(b"\x7fELF"):
        return {"ok": False, "error_code": "no_symdefs",
                "error": "原镜像不是 ELF（裸 bin 没有符号表）：候选里对原镜像函数的调用"
                         "无法解析成绝对地址，只能把候选写成自包含的（不调用外部函数）"}
    try:
        from elftools.elf.elffile import ELFFile     # noqa: PLC0415
        lines = []
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                return {"ok": False, "error_code": "no_symdefs",
                        "error": "ELF 里没有 .symtab（被 strip 过）：无法生成 symdefs"}
            for sym in symtab.iter_symbols():
                kind = sym["st_info"]["type"]
                shndx = sym["st_shndx"]
                if kind not in ("STT_FUNC", "STT_OBJECT"):
                    continue
                if not isinstance(shndx, int) or shndx == 0:
                    continue
                sec = elf.get_section(shndx)
                if sec is None or sec.name.startswith(
                        (".debug", ".symtab", ".strtab", ".shstrtab", ".comment", ".note")):
                    continue
                if not sym.name:
                    continue
                lines.append("0x%08X %s %s" % (
                    int(sym["st_value"]), "T" if kind == "STT_FUNC" else "D", sym.name))
        if not lines:
            return {"ok": False, "error_code": "no_symdefs",
                    "error": "符号表里没有函数/数据符号可用"}
        return {"ok": True, "text": "\n".join(lines) + "\n", "count": len(lines)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error_code": "no_symdefs",
                "error": "读符号表失败：%s: %s" % (type(e).__name__, e)}


def _link(linker: str, work_dir: str, *, obj: str, symdefs: str, entry: str,
          cpu: str, ro_base: int, rw_base: int) -> dict:
    out = os.path.join(work_dir, LINK_NAME)
    cmd = [linker, "--cpu", cpu[0].upper() + cpu[1:] if cpu else "Cortex-M4",
           "--ro-base", "0x%08X" % ro_base, "--rw-base", "0x%08X" % rw_base,
           "--entry", entry, "-o", out]
    if symdefs:
        cmd.append("--symdefs=%s" % symdefs)
    cmd.append(obj)
    try:
        import subprocess                            # noqa: PLC0415
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=180, cwd=work_dir)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "调用 armlink 失败：%s" % e, "cmd": cmd}
    text = ((p.stdout or "") + (p.stderr or "")).strip()
    if p.returncode != 0 or not os.path.isfile(out):
        return {"ok": False, "error_code": "link_failed", "cmd": cmd,
                "error": "链接失败", "stderr": text[:MAX_STDERR],
                "hint": "常见原因：候选调用了原镜像里没有的符号（需要给 -I/声明），"
                        "或 ro_base/rw_base 和镜像重叠"}
    return {"ok": True, "axf": out, "cmd": cmd, "stdout": text[:MAX_STDERR]}


def _load_all(path: str, base: int = 0, exclude=None) -> dict:
    """把镜像**所有**带地址的字节读出来（含 RW/ZI），parity 需要两侧同一份初值。

    与 ``emulate._load_image`` 的差别：那边只映射可执行段（免得数据段遮住外设访问），
    这边要把候选的 RW/ZI 也映射上，否则候选一写全局变量就以 ``unmapped_access`` 停下。

    armlink 的 ``ER_ZI`` 是 **SHT_NOBITS 节**、不在任何 PT_LOAD 里，所以段之外还要
    补一遍有地址的节（PROGBITS 未覆盖的也不放过）。``exclude`` 里的区间由调用方自己
    映射（模拟器给原镜像 RAM 预留的那块零区就是这种），这里跳过。
    """
    data, err = _recover._read_file(path)
    if err:
        return err
    def _skip(addr: int, size: int) -> bool:
        for lo, hi in (exclude or []):
            if addr >= lo and addr + max(size, 1) <= hi:
                return True
        return False

    regions = []
    if data.startswith(b"\x7fELF"):
        from elftools.elf.elffile import ELFFile      # noqa: PLC0415
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                filesz = int(seg["p_filesz"] or 0)
                memsz = int(seg["p_memsz"] or 0)
                if not memsz:
                    continue
                body = data[int(seg["p_offset"]):int(seg["p_offset"]) + filesz]
                if _skip(int(seg["p_vaddr"]), memsz):
                    continue
                regions.append({"addr": int(seg["p_vaddr"]) & ~(ALIGN - 1),
                                "data": body, "memsz": max(memsz, len(body)),
                                "start": int(seg["p_vaddr"])})
            for sec in elf.iter_sections():
                name = sec.name or ""
                if not name or name.startswith((".debug", ".symtab", ".strtab",
                                                ".shstrtab", ".comment", ".note")):
                    continue
                addr = int(sec["sh_addr"] or 0)
                size = int(sec["sh_size"] or 0)
                if not addr or not size:
                    continue
                if any(r["start"] == addr for r in regions):
                    continue
                if _skip(addr, size):
                    continue
                body = b"" if sec["sh_type"] == "SHT_NOBITS" else sec.data()
                regions.append({"addr": addr & ~(ALIGN - 1), "data": body,
                                "memsz": max(size, len(body)), "start": addr})
        return {"ok": True, "regions": regions, "container": "elf",
                "sha256": _recover.sha256_bytes(data), "size": len(data)}
    u = _recover.Unit(data, path, base=int(base or 0), infer_base=False)
    return {"ok": True, "regions": [{"addr": u.base, "data": data, "memsz": len(data),
                                     "start": u.base}],
            "container": "bin", "sha256": _recover.sha256_bytes(data),
            "size": len(data), "entry": 0, "arch": u.arch}


def _span(regions: list) -> tuple:
    lo, hi = None, None
    for r in regions:
        a = int(r["addr"])
        b = a + max(int(r.get("memsz") or 0), len(r.get("data") or b""))
        lo = a if lo is None else min(lo, a)
        hi = b if hi is None else max(hi, b)
    return (lo or 0), (hi or 0)


def _overlaps(regions: list) -> list:
    spans = sorted((int(r["addr"]), int(r["addr"]) + max(int(r.get("memsz") or 0),
                                                        len(r.get("data") or b"")))
                   for r in regions)
    out = []
    for i in range(1, len(spans)):
        if spans[i][0] < spans[i - 1][1]:
            out.append(["0x%08X-0x%08X" % spans[i - 1], "0x%08X-0x%08X" % spans[i]])
    return out


def _auto_ro_base(orig: list, size_hint: int) -> int:
    """候选代码段默认落点：原镜像末尾再往上，避开外设段与未映射的安全区。"""
    _, hi = _span(orig)
    base = ((hi + ALIGN - 1) // ALIGN) * ALIGN
    if base < 0x08000000:
        base = 0x08000000
    if EM.PERIPH_LO <= base < EM.PERIPH_HI:
        base = EM.PERIPH_HI + ALIGN
    return base


def _writes_map(res: dict) -> dict:
    out = {}
    for w in res.get("writes") or []:
        out[(w["addr"], w["size"])] = w["value"]
    return out


def _fmt_writes(items: list) -> list:
    return ["%s[%d]=%s" % (a, s, v) for (a, s), v in items[:50]]


def run(path: str, source: str = "", base: int = 0, target: str | int = 0,
        symbol: str = "", code: str = "", entryname: str = "",
        compiler: str = "auto", cpu: str = "", opt: str = "-O2",
        includes: str = "", args: str = "", max_insns: int = EM.DEFAULT_MAX_INSNS,
        stack: int = EM.DEFAULT_STACK, ram: int = 0x10000,
        timeout_us: int = 2000000, ro_base: int = 0, rw_base: int = 0,
        work_dir: str = "", keep: bool = False) -> dict:
    """编候选 C → 链到空闲地址 → 与原函数跑同一组输入 → 比返回值与写内存。

    判词：

    * ``parity_exact``       两侧都正常返回，r0 一致，且共同地址上的写逐字节一致；
    * ``parity_return_only`` r0 一致，但写内存对不上（值不同，或地址布局不同导致
      只有一侧写了）——返回值对不算等价，写内存也要逐字节对得上才是 ``exact``；
    * ``parity_differs``     r0 不同——这条是**真不一致**，不是"没测出来"；
    * ``not_comparable``     任一侧没跑到返回（外设/未映射/预算/异常），或编译链接失败。

    判词只认 r0：AAAPCS 下 r1..r3 在返回那一刻是 caller-saved 残留、随地址布局变，
    拿它们判定会把同源重编误判成不一致；它们单列在 ``same_scratch`` 里供参考。
    """
    s = str(path or "").strip()
    if not s:
        return {"ok": False, "error": "缺少 path"}
    av = available()
    if not av.get("supported"):
        lacks = [m["what"] for m in av["missing"]]
        toolchain = any(x in ("armcc/armclang", "armlink") for x in lacks)
        return {"ok": False, "supported": False, "verdict": "not_supported",
                "error_code": "toolchain_not_found" if toolchain else "emulator_not_found",
                "error": "缺 %s" % "、".join(lacks),
                "missing": av["missing"], "why": av["why"],
                "next_actions": ["补齐 %s 后重试" % "/".join(lacks)]}

    if source and os.path.isfile(str(source)):
        try:
            with open(str(source), "rb") as fh:
                code = fh.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "supported": True, "error": "读 source 失败：%s" % e}
        src_label = os.path.abspath(str(source))
    elif str(code or "").strip():
        src_label = "inline"
    else:
        return {"ok": False, "supported": True,
                "error": "没有候选源码：给 source（存在的 .c 文件）或 code（源码文本）"}
    if b"\x00" in code.encode("utf-8", "replace"):
        return {"ok": False, "supported": True, "error": "源码里有 NUL 字节：不是文本文件"}
    try:
        argv = EM._parse_args(args)
    except ValueError as e:
        return {"ok": False, "supported": True,
                "error": "args 必须是逗号分隔的 32 位整数：%s" % e,
                "hint": "例如 args=\"1,2\"；不给则为全 0"}

    try:
        addr = int(str(target).strip(), 0) if isinstance(target, str) else int(target or 0)
    except ValueError:
        return {"ok": False, "supported": True, "error": "target 必须是地址，收到 %r" % target}

    an = _recover.analyze(s, base=int(base or 0), deep=True)
    unit = an.get("_unit")
    an.pop("_unit", None)
    an.pop("_recover", None)
    if not an.get("ok"):
        return an
    rf = _recover.recover_functions(unit, deep=True)
    funcs = rf.get("functions") or []
    f = None
    if addr:
        f = next((x for x in funcs if int(x["addr"]) == (int(addr) & ~1)), None)
    elif str(symbol or "").strip():
        f = next((x for x in funcs if str(x.get("name") or "") == str(symbol).strip()), None)
    if f is None:
        return {"ok": False, "supported": True,
                "error": "找不到目标函数（给 target 地址或精确 symbol）",
                "function_count": len(funcs)}
    start = int(f["addr"])
    ent_name = str(entryname or f.get("name") or "").strip()
    if not ent_name:
        return {"ok": False, "supported": True,
                "error": "目标函数没有名字：给 entryname（候选里那个函数叫什么）"}

    # ---- 编译候选 ----
    tc = CB.find_compilers()
    want = str(compiler or "auto").strip().lower()
    use_ac6 = (want == "ac6") or (want == "auto" and bool(tc["ac6"]))
    exe = tc["ac6"] if use_ac6 else tc["ac5"]
    if want == "ac5":
        exe, use_ac6 = tc["ac5"], False
    if not exe:
        return {"ok": False, "supported": True, "error_code": "toolchain_not_found",
                "verdict": "not_supported", "error": tc.get("error"),
                "hint": tc.get("hint"), "tried": tc.get("tried")}
    linker = _find_linker(tc)
    if not linker:
        return {"ok": False, "supported": True, "error_code": "toolchain_not_found",
                "verdict": "not_supported", "error": "找不到 armlink（链接候选需要它）",
                "hint": "armlink 与 armcc 同在 <MDK>\\ARM\\ARMCC\\bin，或设 MDK_ARMCC_BIN"}

    own_dir = not work_dir
    wd = os.path.abspath(work_dir) if work_dir else tempfile.mkdtemp(prefix="mdk108_")
    os.makedirs(wd, exist_ok=True)
    try:
        with open(os.path.join(wd, SRC_NAME), "wb") as fh:
            fh.write(code.encode("utf-8"))
        incs = [x.strip() for x in str(includes or "").split(",") if x.strip()]
        cp = CB._compile(exe, wd, cpu=str(cpu or CB._default_cpu(unit)),
                         opt=str(opt or "-O2"), includes=incs, ac6=use_ac6)
        if not cp.get("ok"):
            return {"ok": False, "supported": True, "verdict": "not_comparable",
                    "stage": "compile", "error_code": "compile_failed",
                    "error": cp.get("error"), "stderr": cp.get("stderr") or "",
                    "cmd": cp.get("cmd")}

        # ---- symdefs + 链接 ----
        sd = _symdefs_text(s)
        sym_path = ""
        sym_note = ""
        if sd.get("ok"):
            sym_path = os.path.join(wd, SYM_NAME)
            with open(sym_path, "wb") as fh:
                fh.write(sd["text"].encode("utf-8"))
        else:
            sym_note = sd.get("error") or ""

        ram_window = [(0x20000000, 0x20000000 + int(ram or 0x10000))]
        orig = _load_all(s, base=int(base or 0), exclude=ram_window)
        if not orig.get("ok"):
            return {"ok": False, "supported": True, "stage": "image", "detail": orig}
        ro = int(ro_base or 0) or _auto_ro_base(orig["regions"], len(code))
        rw = int(rw_base or 0) or 0x20000000
        lk = _link(linker, wd, obj=cp["obj"], symdefs=sym_path, entry=ent_name,
                   cpu=str(cpu or CB._default_cpu(unit)), ro_base=ro, rw_base=rw)
        if not lk.get("ok"):
            out = {"ok": False, "supported": True, "verdict": "not_comparable",
                   "stage": "link", "error_code": lk.get("error_code") or "link_failed",
                   "error": lk.get("error"), "stderr": lk.get("stderr") or "",
                   "cmd": lk.get("cmd"), "symdefs_used": bool(sym_path),
                   "symdefs_note": sym_note}
            return out

        cand = _load_all(lk["axf"], exclude=ram_window)
        if not cand.get("ok"):
            return {"ok": False, "supported": True, "stage": "candidate", "detail": cand}
        regions = list(orig["regions"]) + list(cand["regions"])
        clash = _overlaps(regions)
        if clash:
            return {"ok": False, "supported": True, "verdict": "not_comparable",
                    "stage": "layout", "error_code": "layout_conflict",
                    "error": "候选与原镜像的段重叠：%s" % clash,
                    "hint": "给 ro_base/rw_base 换个空闲地址"}
        img = {"regions": regions, "arch": unit.arch,
               "sha256": orig["sha256"], "container": orig["container"]}

        # ---- 跑两侧 ----
        def _go(entry_addr: int) -> dict:
            return EM._run_one(img, entry_addr, argv,
                               max_insns=int(max_insns or EM.DEFAULT_MAX_INSNS),
                               stack=int(stack or EM.DEFAULT_STACK),
                               ram=int(ram or 0x10000),
                               timeout_us=int(timeout_us or 0))

        try:
            ref_res = _go(start)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "supported": True, "verdict": "not_comparable",
                    "stage": "reference", "error_code": "emulate_failed",
                    "error": "%s: %s" % (type(e).__name__, e),
                    "hint": "常见原因：镜像段与候选段落在同一页（改 ro_base/rw_base）"}
        cand_addr = (_find_in_axf(lk["axf"], ent_name)
                     or int(cand.get("entry") or 0))
        if not cand_addr:
            return {"ok": False, "supported": True, "verdict": "not_comparable",
                    "stage": "candidate_entry", "error_code": "entry_not_found",
                    "error": "链接出来的 axf 里找不到候选函数 %r" % ent_name}
        try:
            tgt_res = _go(cand_addr | 1)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "supported": True, "verdict": "not_comparable",
                    "stage": "target", "error_code": "emulate_failed",
                    "error": "%s: %s" % (type(e).__name__, e)}

        # ---- 比对 ----
        # AAPCS：返回值在 r0（64 位/小结构用 r0-r1）。r1..r3 在返回那一刻是
        # caller-saved 残留，随地址布局变——拿它们做判词会把「同源重编」误判成不一致，
        # 所以只报告、不参与判词。
        ret_same = ref_res["return"]["r0"] == tgt_res["return"]["r0"]
        ret_diff = {k: [ref_res["return"][k], tgt_res["return"][k]]
                    for k in ("r0", "r1", "r2", "r3")
                    if ref_res["return"][k] != tgt_res["return"][k]}
        scratch_same = all(ref_res["return"][k] == tgt_res["return"][k]
                           for k in ("r1", "r2", "r3"))
        wa, wb = _writes_map(ref_res), _writes_map(tgt_res)
        common = [k for k in wa if k in wb]
        value_mismatch = [[k[0], k[1], wa[k], wb[k]] for k in common if wa[k] != wb[k]]
        only_ref = [k for k in wa if k not in wb]
        only_tgt = [k for k in wb if k not in wa]

        stopped = []
        for side, res in (("reference", ref_res), ("target", tgt_res)):
            if res.get("stop_reason") != "returned":
                stopped.append({"side": side, "stop_reason": res.get("stop_reason"),
                                "events": (res.get("events") or [])[:4]})
        if stopped:
            verdict = "not_comparable"
        elif not ret_same:
            verdict = "parity_differs"
        elif value_mismatch or only_ref or only_tgt \
                or ref_res["writes_truncated"] or tgt_res["writes_truncated"]:
            verdict = "parity_return_only"
        else:
            verdict = "parity_exact"

        out = {
            "ok": True, "supported": True, "verdict": verdict,
            "artifact_kind": "c_parity", "evidence_only": True,
            "tool_version": _plan.tool_version(),
            "function": {"name": f.get("name") or "", "addr_hex": "0x%08X" % start,
                         "entry_name": ent_name,
                         "candidate_addr_hex": "0x%08X" % (cand_addr & ~1)},
            "inputs": {"args": ["0x%08X" % x for x in argv],
                       "stack": "0x%08X" % int(stack or EM.DEFAULT_STACK),
                       "ram": "0x%08X" % int(ram or 0x10000)},
            "link": {"ro_base": "0x%08X" % ro, "rw_base": "0x%08X" % rw,
                     "symdefs_used": bool(sym_path), "symdefs_note": sym_note,
                     "symdefs_count": sd.get("count") or 0},
            "reference": {"stop_reason": ref_res["stop_reason"],
                          "n_insns": ref_res["n_insns"], "return": ref_res["return"],
                          "n_writes": len(ref_res["writes"])},
            "target": {"stop_reason": tgt_res["stop_reason"],
                       "n_insns": tgt_res["n_insns"], "return": tgt_res["return"],
                       "n_writes": len(tgt_res["writes"])},
            "same_return": ret_same,
            "same_scratch": scratch_same,
            "writes": {"common": len(common), "same_value": len(common) - len(value_mismatch),
                       "value_mismatch": value_mismatch[:50],
                       "only_in_reference": _fmt_writes([(k, wa[k]) for k in only_ref])[:50],
                       "only_in_target": _fmt_writes([(k, wb[k]) for k in only_tgt])[:50]},
            "differences": {"return_r0": None if ret_same else ret_diff,
                            "scratch_r1_r3": {k: [ref_res["return"][k],
                                                  tgt_res["return"][k]]
                                              for k in ("r1", "r2", "r3")
                                              if ref_res["return"][k]
                                              != tgt_res["return"][k]},
                            "return": ret_diff,
                            "value_mismatch": value_mismatch[:50],
                            "stopped": stopped},
            "not_comparable_because": stopped,
            "source": src_label,
            "image": {"path": os.path.abspath(s), "sha256": orig["sha256"],
                      "container": orig["container"]},
        }
        out.pop("not_comparable_because")
        if verdict != "parity_exact":
            out["not_comparable_because"] = stopped
        out["scope"] = ("parity 只在**这一组输入**上成立：``parity_exact`` 说明这组参数下"
                        "返回值与共同地址的写逐字节一致，不说明两个函数等价。外设不建模"
                        "（碰到 0x40000000–0x5FFFFFFF 就停，判 not_comparable）；候选的全局"
                        "变量在 --rw-base 上、原函数的在镜像 RAM 里，**同一变量地址不同**，"
                        "所以只在共同地址上比写值，地址不同的写分列两栏。候选默认链到 "
                        "0x20000000（与原镜像同一块 RAM），布局一致时写值才逐字节可比。"
                        "RW 初值不搬：armlink 的初始化值要在启动时由 scatter-load 复制，"
                        "模拟器不跑启动代码，所以**非零初值的全局变量在两侧都读成 0**。")
        if own_dir and not keep:
            shutil.rmtree(wd, ignore_errors=True)
        else:
            out["work_dir"] = wd
        return out
    finally:
        if own_dir and not keep:
            pass


def _find_in_axf(axf: str, name: str) -> int:
    """在链接产物里按名字找函数，返回带 Thumb 位的入口地址。"""
    try:
        from elftools.elf.elffile import ELFFile      # noqa: PLC0415
        with open(axf, "rb") as fh:
            elf = ELFFile(fh)
            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                return 0
            for sym in symtab.iter_symbols():
                if sym.name == name and sym["st_info"]["type"] == "STT_FUNC":
                    return int(sym["st_value"]) | 1
    except Exception:  # noqa: BLE001
        return 0
    return 0
