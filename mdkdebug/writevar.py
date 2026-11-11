# -*- coding: utf-8 -*-
"""按变量名写回：把「用户给的值」变成「要写进目标的字节」（批次106）。

为什么不用 `calc_expression("x = 1")` 赋值
------------------------------------------
1. **是否有副作用由 Keil 决定**——表达式求值器可能把它当纯计算、也可能真写内存，
   两种行为在不同 Keil 版本/工程设置下不保证一致，代码里没法断言。
2. **失败不报错**：赋值表达式算出来永远「有个值」，调用方看到 ok=true 就以为写进去了。
   真机踩过的同类坑（write_mem 写只读区被静默忽略）在这里只会更隐蔽。

所以这条链路是：**自己算字节 → write_mem → 回读比对**。每一步的中间结果都能摊开给人看。

本模块只做纯计算，不碰 UVSOCK、不碰文件，便于单测：

  norm_type     类型名归一（uint32_t / u32 / int / auto …）
  infer_type    没给类型时按值推断（宁可窄写，不猜宽写）
  encode_value  单值 → 定宽小端字节
  plan          多值/数组 + 符号宽度校验 → 最终 payload

**宁可报错也不猜**：值超出目标宽度、字节数与符号宽度不符、浮点写整数……
全部抛 ValueError 并把「应该怎么写」说清楚，不截断、不四舍五入、不静默成功。
"""
from __future__ import annotations

import re
import struct

from .numparse import parse_int

# 归一后的类型 → 每元素字节数。`raw` 的宽度由值本身决定（hex:...）。
TYPE_WIDTH = {
    "u8": 1, "u16": 2, "u32": 4, "u64": 8,
    "i8": 1, "i16": 2, "i32": 4, "i64": 8,
    "f32": 4, "f64": 8,
    "raw": 0,
}

# 别名表：把 C 类型名、常见缩写、口语写法统一到上表。
_ALIASES = {
    "auto": "", "": "",
    "u8": "u8", "uint8": "u8", "uint8_t": "u8", "byte": "u8", "uchar": "u8",
    "unsignedchar": "u8", "char": "u8", "bool": "u8", "boolean": "u8",
    "u16": "u16", "uint16": "u16", "uint16_t": "u16", "ushort": "u16",
    "unsignedshort": "u16", "word": "u16", "half": "u16",
    "u32": "u32", "uint32": "u32", "uint32_t": "u32", "uint": "u32",
    "unsigned": "u32", "unsignedint": "u32", "dword": "u32", "size_t": "u32",
    "u64": "u64", "uint64": "u64", "uint64_t": "u64", "unsignedlonglong": "u64",
    "i8": "i8", "int8": "i8", "int8_t": "i8", "schar": "i8", "signedchar": "i8",
    "i16": "i16", "int16": "i16", "int16_t": "i16", "short": "i16", "signedshort": "i16",
    "i32": "i32", "int32": "i32", "int32_t": "i32", "int": "i32", "signed": "i32",
    "signedint": "i32", "long": "i32",
    "i64": "i64", "int64": "i64", "int64_t": "i64", "longlong": "i64",
    "f32": "f32", "float": "f32", "single": "f32",
    "f64": "f64", "double": "f64",
    "raw": "raw", "bytes": "raw", "hex": "raw", "binary": "raw",
}

_BOOL_TRUE = {"true", "on", "yes", "high", "set", "1"}
_BOOL_FALSE = {"false", "off", "no", "low", "clear", "reset", "0"}
_FLOAT_RE = re.compile(r"^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?$")


def norm_type(t) -> str:
    """类型名归一。未知类型抛 ValueError（不降级成 u32——那会给错答案）。"""
    s = str(t or "").strip().lower().replace(" ", "").replace("-", "")
    if s in _ALIASES:
        return _ALIASES[s]
    raise ValueError("无法识别的 value_type: %r；可用 auto/int/uint/u8..u64/i8..i64/"
                     "float/double/raw（也接受 uint32_t / int16_t 这类 C 类型名）" % (t,))


def type_width(type_name: str) -> int:
    return int(TYPE_WIDTH.get(norm_type(type_name), 0))


def parse_raw(text) -> bytes:
    """`hex:deadbeef` / `bytes:00 11 22` → bytes。分隔符容忍空格/逗号/下划线。"""
    s = str(text or "")
    body = s.split(":", 1)[1] if ":" in s else s
    body = "".join(body.split())
    for sep in (",", "_", "|", ";"):
        body = body.replace(sep, "")
    if "0x" in body.lower():
        body = "".join(p for p in body.lower().split("0x") if p)
    try:
        return bytes.fromhex(body)
    except ValueError as e:
        raise ValueError("raw 值解析不了：%r（%s）；期望 hex:deadbeef / bytes:00 11 22"
                         % (text, e)) from None


def _is_bool_word(text: str) -> bool:
    return str(text or "").strip().lower() in (_BOOL_TRUE | _BOOL_FALSE)


def _bool_value(text: str) -> int:
    return 1 if str(text).strip().lower() in _BOOL_TRUE else 0


def infer_type(text, width: int = 0) -> str:
    """没给类型时按「值」推断。返回归一类型名。

    规则（照「宁可窄写」）：
      - `hex:...` / `bytes:...` → raw（宽度由值定）
      - true/false/on/off 这类词 → u8（布尔落在 1 字节）
      - 带小数点或指数 → 宽度 8 时 f64，否则 f32
      - 负数 → 有符号；1/2/4/8 字节按符号宽度；未知宽度按取值范围挑最窄的
    """
    s = str(text or "").strip()
    low = s.lower()
    if low.startswith(("hex:", "bytes:", "raw:")):
        return "raw"
    # 只有 true/false/on/off 这类**词**才是布尔；数字 "0"/"1" 走整数推断——
    # 否则数组里写 "1,2,3,4" 会被推成 u8，与按符号宽度分好的元素宽度打架。
    if _is_bool_word(s) and not s.lstrip("+-").isdigit():
        return "u8"
    if _FLOAT_RE.match(s) and not low.startswith("0x") and ("." in s or "e" in low):
        return "f64" if int(width or 0) == 8 else "f32"
    n = parse_int(s, name="value")
    signed = n < 0
    if width in (1, 2, 4, 8):
        return ("i%d" % (width * 8)) if signed else ("u%d" % (width * 8))
    for bits, lo, hi_u, hi_s in ((8, -(1 << 7), 0xFF, (1 << 7) - 1),
                                 (16, -(1 << 15), 0xFFFF, (1 << 15) - 1),
                                 (32, -(1 << 31), 0xFFFFFFFF, (1 << 31) - 1),
                                 (64, -(1 << 63), (1 << 64) - 1, (1 << 63) - 1)):
        if signed and lo <= n <= hi_s:
            return "i%d" % bits
        if not signed and 0 <= n <= hi_u:
            return "u%d" % bits
    raise ValueError("值 %r 超出 64 位整数范围，无法写入" % (text,))


def encode_value(text, type_name: str = "auto", width: int = 0) -> bytes:
    """把一个值编码成定宽小端字节。

    宽度来源优先级：type_name（显式类型）> width（符号宽度）。两者都为 0 时按值推断。
    """
    t = norm_type(type_name)
    if not t:
        t = infer_type(text, width)
    if t == "raw":
        return parse_raw(text)
    if t.startswith("f"):
        w = TYPE_WIDTH[t]
        if int(width or 0) and int(width) != w:
            raise ValueError("值类型是 %s（%d 字节），但目标宽度是 %d 字节："
                             "要么改 value_type，要么确认符号宽度" % (t, w, int(width)))
        try:
            v = float(str(text).strip().rstrip("fF"))
        except (TypeError, ValueError):
            raise ValueError("值 %r 不是合法浮点数（value_type=%s）" % (text, t)) from None
        return struct.pack("<f" if w == 4 else "<d", v)
    # 整数类
    w = TYPE_WIDTH[t]
    if int(width or 0) and int(width) != w:
        # 显式类型与符号宽度冲突：以显式类型为准，但把冲突说清楚（不静默截断）
        if int(width) < w:
            raise ValueError("value_type=%s 占 %d 字节，超过目标宽度 %d 字节——"
                             "写入会被截断，本工具拒绝截断；请改类型或加大 size_bytes"
                             % (t, w, int(width)))
    if _is_bool_word(text):
        n = _bool_value(text)
    else:
        n = parse_int(text, name="value")
    signed = t.startswith("i")
    if signed:
        lo, hi = -(1 << (w * 8 - 1)), (1 << (w * 8 - 1)) - 1
    else:
        lo, hi = 0, (1 << (w * 8)) - 1
    if not (lo <= n <= hi):
        raise ValueError(
            "值 %r 超出 %s 的范围 [%d, %d]——按位截断会写进一个无关的数，"
            "本工具不做截断；请改 value_type（如 i32）或改值" % (text, t, lo, hi))
    return int(n).to_bytes(w, "little", signed=signed)


def format_value(payload: bytes, type_name: str = "") -> dict:
    """把读回的字节格式化成可读值（回读校验后给人看）。"""
    out = {"hex": bytes(payload or b"").hex()}
    n = len(payload or b"")
    if not n:
        return out
    t = ""
    try:
        t = norm_type(type_name)
    except ValueError:
        t = ""
    if t in ("f32", "f64") and n == TYPE_WIDTH[t]:
        out["float"] = struct.unpack("<f" if n == 4 else "<d", payload)[0]
        return out
    if n in (1, 2, 4, 8):
        out["uint"] = int.from_bytes(payload, "little", signed=False)
        out["int"] = int.from_bytes(payload, "little", signed=True)
        if n == 4:
            out["float_as_32bit"] = struct.unpack("<f", payload)[0]
    return out


def plan(value=None, values=None, width: int = 0, value_type: str = "auto",
         allow_partial: bool = False, count: int = 0) -> dict:
    """把用户给的值（单个或数组）变成要写的 payload，并核对符号宽度。

    返回 {payload: bytes, elem_size, count, type, notes: [...]}；
    宽度不符/超范围抛 ValueError（消息里带「应该怎么写」）。
    `count` 是调用方声明的元素个数：给了就与 values 的个数核对，不一致直接报错——
    宁可报错，也不要「按 values 的实际个数」悄悄写进数组的前几格。
    """
    notes = []
    raw_values = []
    if values is not None:
        if isinstance(values, (list, tuple)):
            raw_values = [v for v in values]
        else:
            raw_values = [x for x in re.split(r"[,;\s]+", str(values).strip()) if x]
    if not raw_values:
        if value is None or str(value).strip() == "":
            raise ValueError("必须给 value（单值）或 values（逗号分隔的多值）")
        raw_values = [value]
    if int(count or 0):
        cn = int(count)
        if cn > 1 and values is None:
            raise ValueError("count=%d 是要写的元素个数，配 values 使用；"
                             "只写一个值请用 value 且不传 count" % cn)
        if len(raw_values) != cn:
            raise ValueError("count=%d 与 values 的个数 %d 不一致——"
                             "要么让 count 等于实际值的个数，要么去掉 count"
                             % (cn, len(raw_values)))
    t = norm_type(value_type)
    elem = TYPE_WIDTH[t] if t else 0
    n = len(raw_values)

    if not elem:
        # 没显式类型：先定元素宽度（有符号宽度就整除分给每个元素），再按值推断类型。
        # 数组里若把 "1,2,3,4" 写进 uint32[4]，按第一个值推成 u8 会算成 4 字节、
        # 随后被判「值只占 4 字节、符号 16 字节宽」——那是在用错的宽度量错的东西。
        if width and n > 1 and width % n == 0:
            elem = width // n
            t = infer_type(raw_values[0], elem)
        elif width and n == 1:
            t = infer_type(raw_values[0], width)
            elem = TYPE_WIDTH[t] or len(parse_raw(raw_values[0]))
        else:
            t = infer_type(raw_values[0], 0)
            elem = TYPE_WIDTH[t] or len(parse_raw(raw_values[0]))
            if n > 1:
                notes.append("未给 value_type / 符号宽度，按第一个值推断为 %s（%d 字节/元素）"
                             % (t, elem))

    payload = bytearray()
    types = []
    for i, v in enumerate(raw_values):
        et = t
        if t == "raw":
            b = parse_raw(v)
            types.append("raw")
        else:
            # 数组里每个元素都按同一类型编码（否则宽度会变，没法回读对齐）
            b = encode_value(v, et, elem)
            types.append(et)
        if len(b) != elem:
            if elem == 0:
                elem = len(b)
            elif len(b) != elem:
                raise ValueError("第 %d 个值编码成 %d 字节，与元素宽度 %d 字节不一致——"
                                 "数组只能写同一类型的元素，不同类型请分开调用"
                                 % (i + 1, len(b), elem))
        payload += b

    total = len(payload)
    if width:
        if total > width:
            raise ValueError(
                "值共 %d 字节（%d × %d），超过符号宽度 %d 字节——"
                "写下去会越界覆盖相邻变量，本工具拒绝；请减小 count/值，"
                "或确认是不是选错了变量" % (total, n, elem, width))
        if total < width:
            if allow_partial:
                notes.append("只写前 %d 字节（符号宽 %d 字节，按 allow_partial=true）"
                             % (total, width))
            else:
                raise ValueError(
                    "值只占 %d 字节，符号 '%d 字节' 宽（可能是数组/结构体）——"
                    "要整写请用 values 给满 %d 个元素，或传 allow_partial=true 只写前缀"
                    % (total, width, width // elem if elem else 0))
    return {"payload": bytes(payload), "elem_size": elem, "count": n,
            "type": t, "element_types": types, "notes": notes}
