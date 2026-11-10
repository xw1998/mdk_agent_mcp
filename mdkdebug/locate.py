# -*- coding: utf-8 -*-
"""定位线（批次105）：在镜像里「找东西」，以及「谁在用它」。

这两个能力是逆向里最常被问、但本仓库此前**没有工具出口**的两问：

  * :func:`search` —— 按**字节模式**（十六进制 + ``??`` 通配）或**文本**在镜像里找，
    每个命中给出「文件偏移 → 虚拟地址 → 所属段 → 是否可执行」的完整链路。
    为什么这条链路重要：反汇编工具能给你 ``ldr r3, [pc, #0004]``，但要把它变成
    「这个字面量池里的常量在 .rodata 的哪里、谁还在用同一段字节」，只能靠字节搜索。
    ``recover_strings`` 只找**可打印串**；``find_symbol`` 只认**符号名**；
    ``search_mem`` 搜的是**目标在线内存**。三者都回答不了「这段字节在镜像里出现在哪」。
  * :func:`xrefs` —— 给定一个地址（或符号），列出**谁引用它**：直接调用、分支、
    数据读写（含基址+偏移的常量传播）、字面量池里的代码指针。本仓库早就把这些
    关系算出来了（``reveng.build_xrefs``），但它只作为 ``recover_project`` 的
    ``xrefs.csv`` 副产品流出——「谁调用了这个函数/谁读了这块数据」这个问题
    此前没有直接入口，得先导出整个工程再翻 CSV。

口径（与批次101/102 一致，全部是**证据**不是猜测）：

  * 通配符只影响「匹配」，不影响「地址」：命中位置照样给出偏移与地址两条；
  * 地址映射不上（在段与段之间的空洞里）时 ``addr=None`` 并记进 ``unmapped``，
    **不按基址硬加**——那会把段间距当成连续地址；
  * 交叉引用的 ``confidence`` 沿用 reveng 的三档语义：``observed``（指令里直接写着）、
    ``inferred``（常量传播/间接解析出来的）、``weak``（字面量池里的候选指针）；
    间接调用解析不出目标时不计入 ``referrers``，只计入 ``unresolved``——
    「没找到引用者」与「有引用者但看不到」是两件事，不能混读。

只读：本模块不写任何文件，不碰目标硬件，只解析文件字节。
"""
import os

from . import recover as _recover
from . import semantics as _sem

# 单次扫描的字节上限（与 image.py 的输入上限同量级：不读部分文件来「猜」整体）
MAX_SCAN_BYTES = 32 * 1024 * 1024
# 模式长度上限：再长就该用别的办法（哈希/差分），通配搜索会退化
MAX_PATTERN = 512
# 命中计数上限：到顶就停，并如实报 truncated
MAX_MATCHES = 20000
# 一次返回的上限与默认页
MAX_LIMIT = 1000
DEFAULT_LIMIT = 100
# 每个命中回显的上下文字节（前后各这么多）
DEFAULT_CONTEXT = 16
MAX_CONTEXT = 512

TEXT_ENCODINGS = ("ascii", "gbk", "utf16le", "utf8")
# Python 的编解码器名与对外的说法不是一回事（utf16le 实际叫 utf-16-le）：
# 直接 encode("utf16le") 会抛 LookupError——那是方言问题，不是用户的错。
_CODEC = {"ascii": "ascii", "gbk": "gbk", "utf8": "utf-8", "utf16le": "utf-16-le"}


class PatternError(ValueError):
    """模式写错时的错误（带上出错的位置，别只说「格式不对」）。"""


# ----------------------------------------------------------------------
# 模式解析
# ----------------------------------------------------------------------
def parse_pattern(text: str) -> list:
    """把十六进制字节模式解析成 ``[0x48, 0x8B, None, 0x24]``（``None`` = 任意字节）。

    接受：``"48 8B ?? 24"``、``"488b??24"``、``"48_8B_??_24"``（空格/下划线/逗号忽略）。
    通配写作 ``??`` / ``?`` / ``--``，都表示「这一个字节任意」。
    """
    s = str(text or "")
    if not s.strip():
        raise PatternError("模式为空：至少给一个字节（如 48 8B ?? 24）")
    # 分隔符统一：`--` 是通配（先替换掉），其余 `-` `_` `,` 与空白都当分隔。
    # 这样 "48 8B ?? 24" / "488b??24" / "48-8B--24" 是同一件事。
    norm = s.replace("--", " ?? ").replace("-", " ") \
            .replace("_", " ").replace(",", " ")
    tokens = []
    for tok in norm.split():
        if tok in ("?", "??", "**"):
            tokens.append(None)
            continue
        if len(tok) % 2:
            raise PatternError("字节对长度是奇数：%r（十六进制必须两位一组）" % tok)
        for i in range(0, len(tok), 2):
            pair = tok[i:i + 2]
            if pair in ("??", "**"):
                tokens.append(None)
            elif all(c in "0123456789abcdefABCDEF" for c in pair):
                tokens.append(int(pair, 16))
            else:
                raise PatternError("不是十六进制字节：%r（出现在 %r 里）" % (pair, tok))
    if len(tokens) > MAX_PATTERN:
        raise PatternError("模式过长（%d 字节，上限 %d）：再长请改用哈希/差分类工具"
                           % (len(tokens), MAX_PATTERN))
    if all(t is None for t in tokens):
        raise PatternError("模式全是通配符：每个位置都会命中，等于没给模式")
    return tokens


def text_pattern(text: str, encoding: str = "ascii") -> list:
    """把一段文本按指定编码变成字节模式（每个字节都是定值）。"""
    enc = str(encoding or "ascii").strip().lower()
    if enc not in TEXT_ENCODINGS:
        raise PatternError("未知编码 %r：可选 %s" % (encoding, " / ".join(TEXT_ENCODINGS)))
    if text == "" or text is None:
        raise PatternError("文本为空：给一段要搜的字")
    try:
        raw = str(text).encode(_CODEC[enc])
    except UnicodeEncodeError:
        raise PatternError("文本里有 %s 编不出来的字符：换 encoding（gbk / utf8 / utf16le）"
                           % enc)
    if not raw:
        raise PatternError("文本按 %s 编码后是空字节序列" % enc)
    if len(raw) > MAX_PATTERN:
        raise PatternError("文本编码后过长（%d 字节，上限 %d）" % (len(raw), MAX_PATTERN))
    return list(raw)


# ----------------------------------------------------------------------
# 匹配
# ----------------------------------------------------------------------
def _anchor(tokens: list):
    """挑最长的一段定值字节当锚点：先用 bytes.find 跳到候选，再逐字节校验。"""
    best_len, best_start = 0, 0
    i, n = 0, len(tokens)
    while i < n:
        if tokens[i] is None:
            i += 1
            continue
        j = i
        while j < n and tokens[j] is not None:
            j += 1
        if j - i > best_len:
            best_len, best_start = j - i, i
        i = j
    return best_start, bytes(tokens[best_start:best_start + best_len]), best_len


def _match_at(data: bytes, start: int, tokens: list) -> bool:
    for k, want in enumerate(tokens):
        if want is not None and data[start + k] != want:
            return False
    return True


def find_all(data: bytes, tokens: list, *, limit: int = MAX_MATCHES,
             in_ranges=None) -> dict:
    """在 ``data`` 里找所有命中（**重叠命中全部报**）。

    ``in_ranges`` 是「允许命中的文件偏移区间」列表 ``[(lo, hi)]``（半开）——
    用来把搜索限制在地址区间里。命中必须**整段落在同一个区间内**：跨区间的
    命中会把两段不相邻的地址拼成一段看着正常的字节，不能算。
    """
    n = len(tokens)
    if n == 0:
        return {"offsets": [], "truncated": False, "scanned": 0}
    a_start, anchor, a_len = _anchor(tokens)
    offsets = []
    truncated = False
    data_len = len(data)
    pos = 0
    while True:
        idx = data.find(anchor, pos)
        if idx < 0:
            break
        pos = idx + 1              # +1 而不是 +a_len：重叠命中也要报
        start = idx - a_start
        if start < 0 or start + n > data_len:
            continue
        if in_ranges is not None:
            ok = False
            for lo, hi in in_ranges:
                if lo <= start and start + n <= hi:
                    ok = True
                    break
            if not ok:
                continue
        if not _match_at(data, start, tokens):
            continue
        offsets.append(start)
        if len(offsets) >= limit:
            truncated = True
            break
    return {"offsets": offsets, "truncated": truncated, "scanned": data_len,
            "anchor": {"at": a_start, "len": a_len}}


# ----------------------------------------------------------------------
# 偏移 ↔ 地址
# ----------------------------------------------------------------------
def _addr_of(unit, off: int):
    """文件偏移 → ``(addr, span)``；不在任何段里返回 ``(None, None)``。

    **不按 base 硬加**：段与段之间可以有空洞（HEX/S-record 尤其明显），
    硬加会把洞里的字节贴上不存在的地址——那正是「看着权威的错答案」。
    """
    for start, end, soff in unit.spans:
        if soff <= off < soff + (end - start):
            return start + (off - soff), (start, end)
    return None, None


def _offset_ranges(unit, start: int, end: int):
    """把地址区间 ``[start, end)`` 换成允许命中的文件偏移区间。"""
    if not start and not end:
        return None
    out = []
    for s, e, soff in unit.spans:
        lo = max(s, start) if start else s
        hi = min(e, end) if end else e
        if hi <= lo:
            continue
        out.append((soff + (lo - s), soff + (hi - s)))
    return out


def _file_section(unit, off: int):
    """文件偏移 → 所属节名（含**非装载节**：.symtab/.strtab/.debug_*）。

    为什么要分开报：命中有 99% 落在“没有地址”的文件区里（符号表、调试信息、
    文件头），说「unmapped」而不说「在哪一节」，等于把一个可核对的事实
    藏成一句含糊的话。
    """
    elf = getattr(unit, "elf", None) or {}
    for s in elf.get("sections") or []:
        if not s.get("size") or s.get("type_name") == "NOBITS":
            continue
        o = s.get("offset") or 0
        if o <= off < o + s["size"]:
            return s.get("name") or None
    return None


def _alloc_ranges(unit):
    """**有地址**的区间（含 .bss/NOBITS：它们没有文件字节，但地址是真的）。

    ``unit.spans`` 只收录「文件里有字节」的节（NOBITS 被跳过），所以拿它判
    「这个地址在不在镜像里」会把 .bss 里的全局变量全判成「不在」——那正是
    `in_image=false` 曾经给错答案的地方。
    """
    out = []
    elf = getattr(unit, "elf", None) or {}
    secs = elf.get("sections") or []
    for s in secs:
        if not s.get("alloc") or not s.get("size"):
            continue
        out.append((s["addr"], s["addr"] + s["size"]))
    if not out:
        out = [(a, b) for a, b, _o in unit.spans]
    return out


def _region_of(unit, addr):
    if addr is None:
        return None
    for a, b in unit.code_ranges:
        if a <= addr < b:
            return "code"
    return "data"


# ----------------------------------------------------------------------
# 主入口 1：字节 / 文本搜索
# ----------------------------------------------------------------------
def search(path: str, base: int = 0, *, pattern: str = "", text: str = "",
           encoding: str = "ascii", start: int = 0, end: int = 0,
           offset: int = 0, limit: int = DEFAULT_LIMIT,
           max_matches: int = MAX_MATCHES, context: int = DEFAULT_CONTEXT) -> dict:
    """在镜像里找字节模式或文本，命中带「偏移 → 地址 → 段 → 是否可执行」。

    ``pattern`` 与 ``text`` 至少给一个；两个都给时**分别搜、分别报**
    （``matches`` 里的 ``via`` 说明这条来自哪一路），不合并成一个模糊的「都算」。
    """
    path = str(path or "").strip()
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": "文件不存在：%s" % path}
    if not pattern and not text:
        return {"ok": False,
                "error": "至少给一个搜索条件：pattern（十六进制字节，可用 ?? 通配）或 text",
                "next_actions": ["例：pattern=\"48 8B ?? 24\"；或 text=\"AT+CGMR\""]}

    jobs = []                       # [(via, tokens, describe)]
    try:
        if pattern:
            jobs.append(("pattern", parse_pattern(pattern), {"pattern": pattern}))
        if text:
            jobs.append(("text", text_pattern(text, encoding),
                         {"text": text, "encoding": encoding}))
    except PatternError as e:
        return {"ok": False, "error": str(e)}

    size = os.path.getsize(path)
    if size > MAX_SCAN_BYTES:
        return {"ok": False, "path": os.path.abspath(path), "size": size,
                "error": "输入超过 %d MiB 上限：本工具不在部分文件上给「没找到」的结论"
                         % (MAX_SCAN_BYTES // (1024 * 1024)),
                "next_actions": ["先 image_split / image_carve 切成几块再搜；"
                                 "或用 recover_strings 定向取串"]}

    an = _recover.analyze(path, base=int(base or 0), deep=False, max_functions=1)
    if not an.get("ok"):
        an.pop("_unit", None)
        an.pop("_recover", None)
        return an
    unit = an.get("_unit")
    if unit is None:
        return {"ok": False, "error": "内部错误：剖析没有给出可寻址的镜像"}
    data = unit.data
    spans = [{"start_hex": "0x%08X" % s, "end_hex": "0x%08X" % e}
             for s, e, _o in unit.spans]
    ctx = max(0, min(int(context or 0), MAX_CONTEXT))
    lim = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    skip = max(0, int(offset or 0))
    cap = max(1, min(int(max_matches or MAX_MATCHES), MAX_MATCHES))
    ranges = _offset_ranges(unit, int(start or 0), int(end or 0))

    hits = []
    per_via = []
    truncated = False
    unmapped = 0
    unmapped_sections = {}
    for via, tokens, describe in jobs:
        r = find_all(data, tokens, limit=cap, in_ranges=ranges)
        truncated = truncated or bool(r["truncated"])
        per_via.append(dict(describe, via=via, bytes=len(tokens),
                            matches=len(r["offsets"]), truncated=bool(r["truncated"])))
        for off in r["offsets"]:
            addr, span = _addr_of(unit, off)
            if addr is None:
                unmapped += 1
                sec = _file_section(unit, off)
                if sec:
                    unmapped_sections[sec] = unmapped_sections.get(sec, 0) + 1
            hits.append((via, off, addr, span))
    # 按文件偏移排序（两路一起看时顺序才有意义）；同一偏移两路都命中就都留着，
    # 因为 via 不同意味着「用不同方法找到了同一处」，这本身是信息。
    hits.sort(key=lambda x: (x[1], x[0]))

    total = len(hits)
    page = hits[skip:skip + lim]
    matches = []
    for via, off, addr, span in page:
        matched = data[off:off + _tokens_len(jobs, via)]
        before = data[max(0, off - ctx):off]
        after = data[off + len(matched):off + len(matched) + ctx]
        matches.append({
            "via": via,
            "file_offset": off,
            "file_offset_hex": "0x%X" % off,
            "addr": addr,
            "addr_hex": ("0x%08X" % addr) if addr is not None else None,
            "region": _region_of(unit, addr),
            "file_section": _file_section(unit, off),
            "span": ({"start_hex": "0x%08X" % span[0], "end_hex": "0x%08X" % span[1]}
                     if span else None),
            "match_hex": matched[:64].hex(),
            "match_truncated": len(matched) > 64,
            "before_hex": before.hex(),
            "after_hex": after.hex(),
        })

    out = {
        "ok": True,
        "input": {"path": an.get("path") or os.path.abspath(path),
                  "size": an.get("size"), "sha256": an.get("sha256"),
                  "container": unit.container},
        "address_basis": {"base_used": unit.base_used,
                          "base_used_hex": "0x%08X" % unit.base_used,
                          "base_source": unit.base_source,
                          "spans": spans,
                          "note": "addr 由「文件偏移 → 所在段」换算，"
                                  "不在任何段里的命中 addr=null（不按基址硬加）"},
        "searched": per_via,
        "range": ({"start_hex": ("0x%08X" % int(start)) if start else None,
                   "end_hex": ("0x%08X" % int(end)) if end else None,
                   "offset_ranges": [{"lo": lo, "hi": hi} for lo, hi in (ranges or [])]}
                  if ranges is not None else None),
        "total": total,
        "returned": len(matches),
        "offset": skip,
        "limit": lim,
        "next_offset": (skip + len(matches)) if (skip + len(matches)) < total else None,
        "truncated": truncated,
        "unmapped": unmapped,
        "unmapped_sections": dict(sorted(unmapped_sections.items(),
                                         key=lambda kv: -kv[1])),
        "matches": matches,
    }
    if truncated:
        out["truncated_reason"] = ("命中数达到 max_matches=%d 后停止计数："
                                   "总数是**下限**，不是全部" % cap)
    out["limitations"] = [
        "字节搜索只说明「这些字节出现在这里」，不说明它是指令、数据还是巧合；"
        "短模式（1~2 字节）在 32 位常量的低位上会命中很多次",
        "「没找到」只对**本次扫描范围**成立：给了 start/end 就只在那个地址区间里找",
        "重叠命中全部报告（同一段字节的开头每挪一位都算一条），"
        "真实用例里看 count 与 addr 分布更可靠",
    ]
    if unmapped:
        out["limitations"].append(
            "有 %d 条命中落在没有地址的文件区里（addr=null），按节统计在 "
            "unmapped_sections：符号表/调试信息/文件头里的字节在文件里真实存在，"
            "但它们是**链接期元数据，不是要被烧进芯片的内容**" % unmapped)
    return out


def _tokens_len(jobs, via) -> int:
    for v, tokens, _d in jobs:
        if v == via:
            return len(tokens)
    return 0


# ----------------------------------------------------------------------
# 主入口 2：交叉引用（谁在用它）
# ----------------------------------------------------------------------
_KIND_ORDER = ("call", "branch", "data_read", "data_write", "data_code_pointer")


def xrefs(path: str, base: int = 0, *, target: str = "", symbol: str = "",
          kinds: str = "", max_refs: int = 200, deep: bool = True,
          max_insns: int = 0, max_functions: int = 0) -> dict:
    """列出「谁引用了这个地址/符号」。

    ``target`` 可以是地址（``0x08000100`` / 十进制）或符号名；``symbol`` 是显式
    符号名入口。两者都空则报错——**没有目标就不猜目标**。
    """
    path = str(path or "").strip()
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": "文件不存在：%s" % path}
    if not str(target or "").strip() and not str(symbol or "").strip():
        return {"ok": False,
                "error": "没有目标：给 target（地址或符号名）或 symbol",
                "next_actions": ["先用 recover_symbols 看有哪些函数，"
                                 "或 recover_probe 看向量表"]}

    kw = {}
    if int(max_functions or 0) > 0:
        kw["max_functions"] = int(max_functions)
    if int(max_insns or 0) > 0:
        kw["max_insns"] = int(max_insns)
    unit, insns, funcs, rel, gaps = _sem._open(
        path, int(base or 0), deep=bool(deep), **kw)
    if unit is None:
        return gaps if isinstance(gaps, dict) else {"ok": False, "error": str(gaps)}

    # ---- 解目标 ----
    name = str(symbol or "").strip()
    raw = str(target or "").strip()
    addr = 0
    resolved = {"how": None, "name": name or None, "addr": None}
    symtab = _recover.symbol_table(unit)
    all_syms = list(symtab.get("functions") or []) + list(symtab.get("objects") or [])
    if raw and not name:
        # 先当符号名找（"main" 这类），找不到再当数字
        hit = [s for s in all_syms if s["name"] == raw]
        if hit:
            name = raw
            addr = int(hit[0]["addr"] or hit[0]["value"] or 0)
            resolved["how"] = "symbol:exact"
        else:
            try:
                addr = int(raw, 0) if raw[:2].lower() in ("0x", "0b", "0o") \
                    else int(raw, 10)
                resolved["how"] = "address"
            except ValueError:
                near = sorted({s["name"] for s in all_syms
                               if raw.lower() in s["name"].lower()
                               or s["name"].lower() in raw.lower()})[:20]
                return {"ok": False,
                        "error": "target=%r 既不是符号名也不是数字地址" % raw,
                        "candidates": near,
                        "next_actions": ["符号名要精确匹配（大小写敏感）；"
                                         "十六进制地址写 0x08000100",
                                         "candidates 里是按子串匹配到的近似名"]}
    if name:
        hit = [s for s in all_syms if s["name"] == name]
        if not hit:
            cands = sorted({s["name"] for s in all_syms
                            if name.lower() in s["name"].lower()})[:20]
            return {"ok": False,
                    "error": "符号表里没有 %r（本镜像的符号表%s）"
                             % (name, "可用" if symtab.get("available")
                                else "不可用：没有 .symtab"),
                    "candidates": cands,
                    "next_actions": ["用 candidates 里的精确名再试；"
                                     "没有符号表时改用地址（先 recover_symbols 找入口）"]}
        rec = hit[0]
        addr = int(rec.get("addr") if rec.get("addr") is not None
                   else rec.get("value") or 0)
        if not resolved["how"]:
            resolved["how"] = "symbol:exact"
        resolved["symbol"] = {"name": rec["name"], "size": rec.get("size"),
                              "type": rec.get("type"), "bind": rec.get("bind"),
                              "confidence": rec.get("confidence")}
    resolved["name"] = name or None
    resolved["addr"] = addr
    resolved["addr_hex"] = "0x%08X" % addr

    want = {k.strip() for k in str(kinds or "").replace(";", ",").split(",") if k.strip()}
    bad = want - set(_KIND_ORDER)
    if bad:
        return {"ok": False,
                "error": "未知的 kinds：%s" % ", ".join(sorted(bad)),
                "next_actions": ["可选：%s（逗号分隔，空=全部）"
                                 % ", ".join(_KIND_ORDER)]}

    xr = ((rel or {}).get("xrefs") or {})   # _relations["xrefs"] 就是 build_xrefs 的返回值
    xs = xr.get("xrefs") or []
    lim = max(1, min(int(max_refs or 200), 5000))
    hits = []
    for x in xs:
        to = x.get("to")
        if to is None:
            continue
        to = int(to)
        # 调用/分支目标在 reveng 里已经归一（清掉 Thumb 位），这里三种写法都认，
        # 免得「0x08000101 找不到」这种假阴性
        if to not in (addr, addr & ~1, addr | 1):
            continue
        kind = x.get("kind") or ""
        if want and kind not in want:
            continue
        hits.append({
            "kind": kind,
            "from": x.get("from"),
            "from_hex": x.get("from_hex"),
            "func": {"addr": x.get("func"),
                     "addr_hex": ("0x%08X" % x["func"]) if x.get("func") else None,
                     "name": x.get("func_name") or None},
            "insn": x.get("insn"),
            "how": x.get("how"),
            "confidence": x.get("confidence"),
            "access": x.get("access"),
            "width": x.get("width"),
            "member": x.get("member"),
            "base_reg": x.get("base_reg"),
        })
    by_kind = {}
    for h in hits:
        by_kind[h["kind"]] = by_kind.get(h["kind"], 0) + 1
    truncated = len(hits) > lim
    shown = hits[:lim]

    # ---- 这个地址是不是函数入口 / 在不在向量表里 ----
    entry = [f for f in (funcs or []) if int(f.get("addr") or 0) == (addr & ~1)]
    vt = _recover.vector_table(unit)
    vt_hit = []
    for e in ((vt or {}).get("entries") or []):
        hx = e.get("handler_hex")
        if not hx:
            continue
        try:
            val = int(hx, 16)
        except (TypeError, ValueError):
            continue
        if val in (addr, addr & ~1, addr | 1):
            vt_hit.append({"index": e.get("index"),
                           "handler_hex": hx,
                           "exception": e.get("name"),
                           "thumb": e.get("thumb"),
                           "semantics": (vt or {}).get("semantics")})
    unres = int(xr.get("n_unresolved") or 0)

    out = {
        "ok": True,
        "input": {"path": os.path.abspath(path),
                  "size": os.path.getsize(path),
                  "container": unit.container,
                  "base_used_hex": "0x%08X" % unit.base_used},
        "target": resolved,
        "in_image": bool(addr and any(s <= (addr & ~1) < e
                                      for s, e in _alloc_ranges(unit))),
        "in_code": bool(entry) or _region_of(unit, addr & ~1) == "code",
        "is_function_entry": bool(entry),
        "function": ({"addr_hex": "0x%08X" % int(entry[0]["addr"]),
                      "name": entry[0].get("name"),
                      "size": entry[0].get("size"),
                      "confidence": entry[0].get("confidence")} if entry else None),
        "in_vector_table": vt_hit,
        "total": len(hits),
        "returned": len(shown),
        "by_kind": by_kind,
        "referrers": shown,
        "unresolved": unres,
        "truncated": truncated,
        "counts_all": xr.get("counts") or {},
        "gaps": gaps or [],
        "limitations": [
            "「没有引用者」不等于「没人用它」：间接调用（blx rN）解析不出目标时"
            "只计入 unresolved（本次 %d 条），函数指针表/中断向量/自修改代码同样看不到" % unres,
            "confidence=observed 指指令里直接写着这个目标；inferred 指常量传播算出来的"
            "（依赖前面几条指令的 mov/movt/add）；weak 指字面量池里有个指向代码的指针",
            "data_read/data_write 的地址来自基址寄存器常量传播，会被寄存器别名打断；"
            "看不到不等于没访问",
            "本工具报的是**这个精确地址**的引用；落在结构体/数组中间某个成员的访问"
            "只在 base_reg/member 字段里体现，需要按 member 偏移自己汇总",
        ],
    }
    if truncated:
        out["truncated_reason"] = ("引用超过 max_refs=%d：只返回前 %d 条，"
                                   "by_kind 与 total 统计的是全部" % (lim, lim))
    return out
