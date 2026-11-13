# -*- coding: utf-8 -*-
"""行为 oracle：在模拟器里跑原机器码（批次107）。

静态分析能回答「这段码长什么样」，回答不了「它到底做了什么」。这一层补的就是后者：
把镜像按段映射进 Unicorn，设好寄存器与栈，从函数入口跑一段，把**可观测的结果**
（返回寄存器 r0、写过的内存、碰到未映射地址/外设的时机）记下来。两个镜像用同一组
输入跑，可以逐项对比——这就是「差分」。

三条边界，写在最前面：

1. **unicorn 是可选依赖**。没装就 ``supported: false`` 并给安装命令，**不降级成静态猜测**。
   本模块的所有函数在没装 unicorn 时也能 import（lazy import）；
2. **外设不可模拟**。Cortex-M 的外设寄存器（0x40000000–0x5FFFFFFF 这一段）在真机上
   是硬件行为，模拟器里读回来是 0。碰到外设访问时**停下来**并如实记 ``peripheral_access``，
   不假装跑完了——否则「跑完了、返回值是 0」会被读成「函数返回 0」；
3. **跑通不等于正确**。模拟器只执行你给的那段码，不进中断、不等 DMA、不开 FPU 上下文；
   它证明的是「这段码在这些输入下表现如此」，不是「这段码在板子上安全」。
"""
from __future__ import annotations

import os

from . import recover as _recover

PERIPH_LO = 0x40000000
PERIPH_HI = 0x60000000
# 返回哨兵：函数用 bx lr 返回时 PC 走到这里就停（不需要真的映射）
SENTRY = 0xFFFFFFF0
DEFAULT_STACK = 0x1000
DEFAULT_MAX_INSNS = 20000
MAX_WRITES = 512

INSTALL_HINT = "pip install unicorn（或 pip install \"mdkdebug[emu]\"）"


def available() -> dict:
    """unicorn 在不在。"""
    try:
        import unicorn                     # noqa: F401,PLC0415
        from unicorn import arm_const     # noqa: F401,PLC0415
        return {"supported": True, "version": getattr(unicorn, "__version__", "")}
    except Exception as e:  # noqa: BLE001
        return {"supported": False, "error": "%s: %s" % (type(e).__name__, e),
                "hint": INSTALL_HINT,
                "why": "Unicorn 是可选依赖：本仓库默认不引入，缺了就不做行为模拟，"
                       "也不拿静态分析冒充运行结果"}


def _load_image(path: str, base: int) -> dict:
    """读文件 → ``{regions: [{addr, data, memsz}], entry, arch}``。"""
    data, err = _recover._read_file(path)
    if err:
        return err
    if data.startswith(b"\x7fELF"):
        el = _recover.parse_elf(data)
        if not el.get("ok"):
            return {"ok": False, "error": "ELF 解析失败：%s" % el.get("error")}
        regions = []
        for seg in el.get("segments") or []:
            if not seg.get("filesz"):
                continue
            if not (seg.get("flags") or 0) & 0x1:
                continue            # 只映射「可执行」段：数据段一起映射会遮住外设访问
            body = data[seg["offset"]:seg["offset"] + seg["filesz"]]
            regions.append({"addr": seg["vaddr"] & ~0xFFF, "data": body,
                            "memsz": max(seg.get("memsz") or 0, len(body)),
                            "start": seg["vaddr"]})
        return {"ok": True, "regions": regions, "entry": el.get("entry") or 0,
                "arch": _recover.arch_of(el), "container": "elf", "size": len(data),
                "sha256": _recover.sha256_bytes(data)}
    u = _recover.Unit(data, path, base=int(base or 0), infer_base=False)
    return {"ok": True, "regions": [{"addr": u.base, "data": data, "memsz": len(data),
                                     "start": u.base}],
            "entry": 0, "arch": u.arch, "container": "bin", "size": len(data),
            "sha256": _recover.sha256_bytes(data)}


def _parse_args(text) -> list:
    if isinstance(text, (list, tuple)):
        return [int(x) & 0xFFFFFFFF for x in text][:4]
    vals = []
    for tok in str(text or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        vals.append(int(tok, 0) & 0xFFFFFFFF)
    return vals[:4]


def _run_one(img: dict, entry: int, args: list, *, max_insns: int,
             stack: int, ram: int, timeout_us: int) -> dict:
    from unicorn import (Uc, UcError, UC_ARCH_ARM, UC_HOOK_CODE,
                         UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE,
                         UC_HOOK_MEM_WRITE_UNMAPPED)          # noqa: PLC0415
    from unicorn import UC_MODE_THUMB                          # noqa: PLC0415
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_R3, UC_ARM_REG_SP,
                                   UC_ARM_REG_LR, UC_ARM_REG_PC)  # noqa: PLC0415

    page = 0x1000
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    mapped = []
    for r in img["regions"]:
        start = r["addr"] & ~(page - 1)
        total = (max(len(r["data"]), r["memsz"]) + page - 1) & ~(page - 1)
        total = max(total, page)
        uc.mem_map(start, total)
        uc.mem_write(r["start"], r["data"])
        if r.get("memsz", 0) > len(r["data"]):
            uc.mem_write(r["start"] + len(r["data"]), b"\x00" * (r["memsz"] - len(r["data"])))
        mapped.append((start, start + total))
    # RAM：给栈留一块（用 0x20000000，Cortex-M 的 SRAM 典型位置），再补一块可写区
    ram_base = 0x20000000
    ram_size = (int(ram or 0x10000) + page - 1) & ~(page - 1)
    uc.mem_map(ram_base, ram_size)
    mapped.append((ram_base, ram_base + ram_size))
    sp = (ram_base + ram_size - 16) & ~7
    sp -= min(int(stack or DEFAULT_STACK), max(0, ram_size - 64))
    sp &= ~7
    for i, v in enumerate(args):
        uc.reg_write([UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3][i], v)
    uc.reg_write(UC_ARM_REG_SP, sp)
    # LR 不给 Thumb 位：bx lr 之后 PC 是 0xFFFFFFF0（对齐值），emu_start 的 until
    # 必须与**跳转后的 PC** 逐位相等才会停——写 SENTRY|1 会差一位，于是去取指并报
    # UC_ERR_FETCH_UNMAPPED（批次107 实测踩到）。
    uc.reg_write(UC_ARM_REG_LR, SENTRY)

    writes, events = [], []
    state = {"stop": "", "n": 0}

    def on_code(ucx, address, size, _ud):
        state["n"] += 1
        if state["n"] > int(max_insns):
            state["stop"] = "instruction_budget"
            ucx.emu_stop()

    def on_write(ucx, access, address, size, value, _ud):
        if len(writes) < MAX_WRITES:
            writes.append({"addr": "0x%08X" % address, "size": size,
                           "value": "0x%X" % (value & ((1 << (size * 8)) - 1))})
        return True

    def _is_periph(a: int) -> bool:
        return PERIPH_LO <= a < PERIPH_HI

    def on_write_unmapped(ucx, access, address, size, value, _ud):
        if _is_periph(address):
            events.append({"kind": "peripheral_access", "how": "write",
                           "addr": "0x%08X" % address})
            state["stop"] = "peripheral_access"
        else:
            events.append({"kind": "unmapped_write", "how": "write",
                           "addr": "0x%08X" % address})
            state["stop"] = "unmapped_access"
        ucx.emu_stop()
        return False

    def on_read_unmapped(ucx, access, address, size, value, _ud):
        if _is_periph(address):
            events.append({"kind": "peripheral_access", "how": "read",
                           "addr": "0x%08X" % address})
            state["stop"] = "peripheral_access"
        else:
            events.append({"kind": "unmapped_read", "how": "read",
                           "addr": "0x%08X" % address})
            state["stop"] = "unmapped_access"
        ucx.emu_stop()
        return False

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, on_write_unmapped)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, on_read_unmapped)

    begin = int(entry) | 1        # Thumb 位
    try:
        uc.emu_start(begin, SENTRY, timeout=int(timeout_us or 0),
                     count=int(max_insns) + 16)
    except UcError as e:
        if not state["stop"]:
            state["stop"] = "error"
        events.append({"kind": "uc_error", "detail": str(e)})

    def reg(r):
        try:
            return int(uc.reg_read(r)) & 0xFFFFFFFF
        except Exception:  # noqa: BLE001
            return None

    pc = reg(UC_ARM_REG_PC)
    if not state["stop"]:
        state["stop"] = ("returned" if pc is not None and (pc & ~1) == (SENTRY & ~1)
                         else "pc_outside")
    return {
        "stop_reason": state["stop"],
        "n_insns": state["n"],
        "return": {"r0": "0x%08X" % reg(UC_ARM_REG_R0),
                   "r1": "0x%08X" % reg(UC_ARM_REG_R1),
                   "r2": "0x%08X" % reg(UC_ARM_REG_R2),
                   "r3": "0x%08X" % reg(UC_ARM_REG_R3),
                   "pc": "0x%08X" % (pc or 0)},
        "writes": writes,
        "writes_truncated": len(writes) >= MAX_WRITES,
        "events": events,
    }


def run(path: str, entry: str | int = 0, base: int = 0, args: str = "",
        symbol: str = "", max_insns: int = DEFAULT_MAX_INSNS,
        stack: int = DEFAULT_STACK, ram: int = 0x10000,
        timeout_us: int = 2000000) -> dict:
    """在模拟器里跑一个函数，返回 r0..r3 / 写过的内存 / 停下来的原因。"""
    av = available()
    if not av.get("supported"):
        return {"ok": False, "supported": False, "verdict": "not_supported",
                **{k: v for k, v in av.items() if k != "supported"},
                "next_actions": ["装 unicorn 后重试；没有它就不做行为模拟"]}
    path = str(path or "").strip()
    if not path:
        return {"ok": False, "error": "缺少 path", "supported": True}
    img = _load_image(path, int(base or 0))
    if not img.get("ok"):
        return img
    if not (img["arch"] or {}).get("supported"):
        return {"ok": False, "supported": True, "verdict": "not_supported",
                "error": "架构未判定（%s）：模拟必须知道指令集，工具不猜"
                         % (img["arch"] or {}).get("why", ""),
                "hint": "显式给 base 让向量表可判，或换带 ELF 头的镜像"}
    ent = int(entry) if not isinstance(entry, str) else int(str(entry).strip() or "0", 0)
    if not ent and str(symbol or "").strip():
        an = _recover.analyze(path, base=int(base or 0), deep=False)
        unit = an.get("_unit")
        if unit is None:
            return {"ok": False, "supported": True,
                    "error": "无法剖析镜像来解析符号：%s" % (an.get("error") or "")}
        rf = _recover.recover_functions(unit, deep=False)
        hit = next((f for f in rf.get("functions") or []
                    if str(f.get("name") or "") == str(symbol).strip()), None)
        if hit is None:
            return {"ok": False, "supported": True,
                    "error": "符号 %r 不是已知函数（要精确名字）" % symbol}
        ent = int(hit["addr"])
    if not ent:
        return {"ok": False, "supported": True,
                "error": "必须给 entry（地址）或 symbol（精确函数名）"}
    try:
        argv = _parse_args(args)
    except ValueError as e:
        return {"ok": False, "supported": True,
                "error": "args 必须是逗号分隔的整数（可 0x 前缀）：%s" % e}
    res = _run_one(img, ent, argv, max_insns=int(max_insns or DEFAULT_MAX_INSNS),
                   stack=int(stack or DEFAULT_STACK), ram=int(ram or 0x10000),
                   timeout_us=int(timeout_us or 0))
    return {"ok": True, "supported": True, "verdict": "ran",
            "artifact_kind": "emulate", "evidence_only": True,
            "entry_hex": "0x%08X" % (ent & ~1),
            "args": ["0x%08X" % x for x in argv],
            "image": {"path": os.path.abspath(path), "sha256": img["sha256"],
                      "container": img["container"],
                      "regions": [{"start_hex": "0x%08X" % r["start"],
                                   "bytes": len(r["data"])} for r in img["regions"]]},
            "result": res,
            "scope": ("模拟器只执行这段码：不进中断、不等 DMA、不建模外设与 FPU 上下文。"
                      "「跑完了」不等于「在板子上安全」；碰到外设访问会停下，"
                      "那时看到的内存/寄存器只是**停下那一刻**的状态"),
            }


def diff(path: str, reference: str = "", entry: str | int = 0,
         base: int = 0, base_reference: int = 0, args: str = "",
         symbol: str = "", max_insns: int = DEFAULT_MAX_INSNS,
         stack: int = DEFAULT_STACK, ram: int = 0x10000,
         timeout_us: int = 2000000) -> dict:
    """两个镜像、同一组输入，比可观测结果（r0..r3 与内存写序列）。

    典型用法：原厂固件 vs 自己重编译的固件，确认「行为一致」；或者候选实现 vs 原函数。
    """
    av = available()
    if not av.get("supported"):
        return {"ok": False, "supported": False, "verdict": "not_supported",
                **{k: v for k, v in av.items() if k != "supported"}}
    a = run(path, entry=entry, base=base, args=args, symbol=symbol,
            max_insns=max_insns, stack=stack, ram=ram, timeout_us=timeout_us)
    if not a.get("ok"):
        return {"ok": False, "supported": True, "stage": "reference", "detail": a}
    b = run(str(reference or "").strip(), entry=entry, base=base_reference, args=args,
            symbol=symbol, max_insns=max_insns, stack=stack, ram=ram,
            timeout_us=timeout_us)
    if not b.get("ok"):
        return {"ok": False, "supported": True, "stage": "target", "detail": b}
    ra, rb = a["result"], b["result"]
    same_regs = all(ra["return"][k] == rb["return"][k] for k in ("r0", "r1", "r2", "r3"))
    wa = [(w["addr"], w["size"], w["value"]) for w in ra["writes"]]
    wb = [(w["addr"], w["size"], w["value"]) for w in rb["writes"]]
    return {
        "ok": True, "supported": True, "verdict": "compared",
        "artifact_kind": "emulate_diff", "evidence_only": True,
        "same_return": same_regs,
        "same_writes": wa == wb,
        "reference": {"image": a["image"], "result": ra},
        "target": {"image": b["image"], "result": rb},
        "differences": {
            "return": {k: [ra["return"][k], rb["return"][k]]
                       for k in ("r0", "r1", "r2", "r3")
                       if ra["return"][k] != rb["return"][k]},
            "writes_only_in_reference": [x for x in wa if x not in wb][:50],
            "writes_only_in_target": [x for x in wb if x not in wa][:50],
        },
        "scope": ("差分只在**这一组输入**上成立：同一份代码对不同参数可以完全一致也可"
                  "完全不一致。外设访问会让一侧提前停下，那时 same_* 的比较没有意义——"
                  "先看两侧 stop_reason"),
    }
