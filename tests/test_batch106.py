# -*- coding: utf-8 -*-
"""批次106 测试：写变量 / 区间转储 / Modbus 点表。

本批补的是「此前根本没有出口」的三件事：

  write_variable   按变量名写回。不走 calc_expression("x = 1")——是否有副作用由 Keil
                   决定、写失败也不报错；改成「自己算字节 → write_mem → 回读比对」，
                   并把宽度来源（size_bytes > sizeof > ELF st_size）与越界拒绝写死。
  dump_memory      区间转储成文件（bin/ihex/hexdump）。分块搬运，某块读失败按 gap_fill
                   补齐并记 gaps + complete=false（补齐字节不是真实内容）；bin 支持按
                   已有文件长度续传；给 sha256 / 吞吐 / 有效字节数。
  modbus_pointmap  多点 × 多采样，按「值怎么变」分类成 constant / bistable / drifting /
                   changing / no_response。语义标 unconfirmed，不替人判定「这是流量」。

分节：

  A 工具面：3 个新工具注册、归组、注解、schema
  B writevar 纯计算：类型归一、按值推断、编码、越界/截断拒绝、数组宽度分配
  C memdump：ihex 记录与校验和、64 KB 边界、gaps 记账、续传、拒绝覆盖、sha256
  D pointmap：五档分类、引用号、analyze 点表、run 采样（假 sampler + 假 sleep）
  E 零依赖与文档 / 版本闸门

运行：python -m tests.test_batch106
"""
import io
import os
import re
import shutil
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import annotate as AN          # noqa: E402
from mdkdebug import memdump as MD           # noqa: E402
from mdkdebug import pointmap as PM          # noqa: E402
from mdkdebug import toolbox as TB           # noqa: E402
from mdkdebug import writevar as WV          # noqa: E402

NEW_TOOLS = ("write_variable", "dump_memory", "modbus_pointmap")
GROUP = {"write_variable": "core", "dump_memory": "mem",
         "modbus_pointmap": "serial"}

PASS, FAIL = [], []
TMP = []

def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:400]), flush=True)

def tmpdir(prefix="mdk106_"):
    d = tempfile.mkdtemp(prefix=prefix)
    TMP.append(d)
    return d

def _err(fn, *a, **kw):
    """调用并返回异常消息（调用成功返回空串）。"""
    try:
        fn(*a, **kw)
    except ValueError as e:
        return str(e)
    except Exception as e:                   # noqa: BLE001
        return "WRONG-TYPE:%s" % type(e).__name__
    return ""

# ---------------------------------------------------------------------------
# A 工具面
# ---------------------------------------------------------------------------
def section_a():
    print("\nA 工具面：3 个新工具注册、归组、注解、schema")
    from mdkdebug import server as SV
    import asyncio

    srv = SV.create_server(port=15974, toolsets="all")
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    names = set(tools)
    check("A1 三个新工具都注册了",
          all(n in names for n in NEW_TOOLS),
          [n for n in NEW_TOOLS if n not in names])
    check("A2 注册总数 232（本批新增 3 个，批次105 后为 222）",
          len(names) == 232, len(names))
    check("A3 分组数量对（core 39 / mem 12 / serial 15）",
          len(TB.TOOLSETS["core"]) == 39 and len(TB.TOOLSETS["mem"]) == 12
          and len(TB.TOOLSETS["serial"]) == 15,
          (len(TB.TOOLSETS["core"]), len(TB.TOOLSETS["mem"]),
           len(TB.TOOLSETS["serial"])))
    check("A4 三者各归一组且归到预期组",
          all(sum(1 for g in TB.TOOLSETS if n in TB.TOOLSETS[g]) == 1
              and n in TB.TOOLSETS[GROUP[n]] for n in NEW_TOOLS),
          {n: [g for g in TB.TOOLSETS if n in TB.TOOLSETS[g]] for n in NEW_TOOLS})
    check("A5 三者都不是只读（READONLY 里不能有）",
          all(n not in AN.READONLY for n in NEW_TOOLS),
          [n for n in NEW_TOOLS if n in AN.READONLY])
    check("A6 三者都在 MUTATING 里（check_surface 不变式）",
          all(n in AN.MUTATING for n in NEW_TOOLS),
          [n for n in NEW_TOOLS if n not in AN.MUTATING])
    check("A7 write_variable 标 destructive（与 write_mem 同档）",
          "write_variable" in AN.DESTRUCTIVE
          and AN.annotations_for("write_variable").get("destructiveHint") is True,
          AN.annotations_for("write_variable"))
    check("A8 dump_memory / modbus_pointmap 标 non-idempotent（写文件/重复采样不等价）",
          all(n in AN.NON_IDEMPOTENT
              and AN.annotations_for(n).get("idempotentHint") is False
              for n in ("dump_memory", "modbus_pointmap")),
          [n for n in ("dump_memory", "modbus_pointmap")
           if AN.annotations_for(n).get("idempotentHint") is not False])
    check("A9 工具面归类完整（check_surface 无问题）",
          AN.check_surface(sorted(names)) == [], AN.check_surface(sorted(names)))
    want = {
        "write_variable": {"name", "value", "values", "count", "value_type",
                           "size_bytes", "reloc_delta", "allow_partial",
                           "dry_run", "verify", "running"},
        "dump_memory": {"addr", "size", "path", "format", "chunk", "resume",
                        "overwrite", "gap_fill", "reloc_delta"},
        "modbus_pointmap": {"slave", "func", "addr", "count", "samples",
                            "interval_ms", "port", "baud", "serial_format",
                            "databits", "parity", "stopbits", "mode",
                            "timeout_ms", "include_history", "max_count", "out"},
    }
    bad = {}
    for n, ps in want.items():
        props = set((tools[n].input_schema.get("properties") or {}).keys())
        if not ps <= props:
            bad[n] = sorted(ps - props)
    check("A10 schema 参数名齐全（CLI 靠它生成 --arg）", not bad, bad)

# ---------------------------------------------------------------------------
# B writevar 纯计算
# ---------------------------------------------------------------------------
def section_b():
    print("\nB writevar：类型归一 / 按值推断 / 编码 / 越界拒绝")
    check("B1 C 类型名归一（uint32_t → u32）",
          WV.norm_type("uint32_t") == "u32" and WV.norm_type("u32") == "u32")
    check("B2 口语别名归一（bool / char / word / long / size_t）",
          (WV.norm_type("bool"), WV.norm_type("char"), WV.norm_type("word"),
           WV.norm_type("long"), WV.norm_type("size_t"))
          == ("u8", "u8", "u16", "i32", "u32"))
    m = _err(WV.norm_type, "float32x")
    check("B3 未知类型报错且列出可用类型（不降级成 u32）",
          "无法识别" in m and "u8..u64" in m, m)

    check("B4 类型宽度表（u8/i16/u32/f64/raw）",
          (WV.type_width("u8"), WV.type_width("i16"), WV.type_width("u32"),
           WV.type_width("f64"), WV.type_width("raw")) == (1, 2, 4, 8, 0))

    check("B5 正数按最窄无符号推断", WV.infer_type("300") == "u16", WV.infer_type("300"))
    check("B6 负数按有符号推断", WV.infer_type("-5") == "i8", WV.infer_type("-5"))
    check("B7 带小数按 f32（宽度 8 时 f64）",
          WV.infer_type("1.5") == "f32" and WV.infer_type("1.5", 8) == "f64")
    check("B8 布尔词 / hex: 前缀的类型",
          (WV.infer_type("true"), WV.infer_type("off"),
           WV.infer_type("hex:deadbeef")) == ("u8", "u8", "raw"))

    check("B9 u16 300 编码成小端两字节",
          WV.encode_value("300", "u16") == b"\x2c\x01",
          WV.encode_value("300", "u16").hex())
    check("B10 i8 -1 编码成 0xFF",
          WV.encode_value("-1", "i8") == b"\xff", WV.encode_value("-1", "i8").hex())
    check("B11 f32 1.5 编码正确",
          struct.unpack("<f", WV.encode_value("1.5", "f32"))[0] == 1.5)
    check("B12 raw 支持 hex: / bytes: 两种写法",
          (WV.encode_value("hex:DEADBEEF", "raw"),
           WV.encode_value("bytes:de ad be ef", "raw")) == (b"\xde\xad\xbe\xef",) * 2)
    check("B13 bool 词编码成 1/0",
          WV.encode_value("true", "u8") == b"\x01"
          and WV.encode_value("off", "u8") == b"\x00")

    m = _err(WV.encode_value, "256", "u8")
    check("B14 u8 写 256 被拒（不截断成 0）",
          "超出" in m and "255" in m, m)
    m = _err(WV.encode_value, "128", "i8")
    check("B15 i8 写 128 被拒（有符号上界）", "超出" in m and "127" in m, m)
    m = _err(WV.encode_value, "1", "u32", 2)
    check("B16 类型占 4 字节 > 目标 2 字节时拒绝写（会截断）",
          "截断" in m, m)
    m = _err(WV.encode_value, "abc", "u16")
    check("B17 非数字报错（不猜成 0）", m and "WRONG-TYPE" not in m, m)

    check("B18 format_value 同时给 hex/uint/int（4 字节还解读成 float）",
          WV.format_value(b"\x00\x00\x80\x3f")["float_as_32bit"] == 1.0,
          WV.format_value(b"\x00\x00\x80\x3f"))
    check("B19 format_value 按 f32 类型给出 float",
          abs(WV.format_value(b"\x00\x00\xc0\x3f", "f32")["float"] - 1.5) < 1e-6)

    p = WV.plan(value="5", width=1)
    check("B20 单值按符号宽度推断类型并编码",
          p["payload"] == b"\x05" and p["type"] == "u8" and p["count"] == 1, p)
    p = WV.plan(values="1,2,3,4", width=16)
    check("B21 uint32[4] 的宽度被均分成 4 字节/元素（不推成 u8）",
          p["payload"] == b"\x01\x00\x00\x00\x02\x00\x00\x00"
                           b"\x03\x00\x00\x00\x04\x00\x00\x00" and p["elem_size"] == 4, p)
    m = _err(WV.plan, values="1,2", width=16, value_type="u8")
    check("B22 元素数与符号宽度不符时报错并给「应该给几个」",
          "要整写请用 values" in m and "16 个元素" in m, m)
    m = _err(WV.plan, values="1,2", count=3)
    check("B23 count 与实际值个数不符被拒", "count=3" in m, m)
    m = _err(WV.plan, value="1", count=2)
    check("B24 只给 value 却传 count>1 被拒（别悄悄写前几格）", "配 values" in m, m)
    m = _err(WV.plan)
    check("B25 什么都不给报错", "必须给 value" in m, m)
    m = _err(WV.plan, values="1,2,3,4,5,6,7,8,9", width=8, value_type="u8")
    check("B26 总字节数超符号宽度被拒（越界覆盖相邻变量）", "越界" in m, m)
    p = WV.plan(values="1,2", width=16, value_type="u8", allow_partial=True)
    check("B27 allow_partial=true 只写前缀并留 note",
          p["payload"] == b"\x01\x02" and p["notes"], p)

# ---------------------------------------------------------------------------
# C memdump
# ---------------------------------------------------------------------------
def _ihex_ok(line):
    hx = line.strip()[1:]
    raw = bytes.fromhex(hx)
    return (sum(raw) & 0xFF) == 0

def section_c():
    print("\nC memdump：ihex 校验 / 64 KB 边界 / gaps / 续传 / 拒绝覆盖")
    lines, upper = MD.ihex_records(0x08000000, bytes(range(64)))
    check("C1 记录行以冒号开头且校验和自洽",
          all(l.startswith(":") and _ihex_ok(l) for l in lines), lines[:3])
    check("C2 首行先声明扩展线性地址（04 记录）+ 其后才是数据记录",
          len(lines) == 5 and bytes.fromhex(lines[0][1:])[3] == 0x04, lines[0])
    check("C3 upper 被带出（供分批追加时复用）", upper == 0x0800, upper)

    lines2, up2 = MD.ihex_records(0x08000010, bytes(16), 16, upper)
    check("C4 同一高 16 位不重复声明扩展地址（upper 复用）",
          len(lines2) == 1 and up2 == 0x0800, lines2)

    # 0x0800FFFF 起 32 字节：第一条记录只能写 1 字节，剩下的进下一条并触发 04 记录
    lines3, up3 = MD.ihex_records(0x0800FFFF, bytes(range(32)))
    recs = [bytes.fromhex(l[1:]) for l in lines3]
    data_recs = [r for r in recs if r[3] == 0x00]
    check("C5 记录不跨 64 KB 边界（首条只写 1 字节）",
          data_recs[0][0] == 1, [r[0] for r in data_recs])
    check("C6 跨界后重新声明扩展地址（upper 变 0x0801）", up3 == 0x0801, up3)
    check("C7 全部记录校验和自洽", all(_ihex_ok(l) for l in lines3))

    check("C8 EOF 记录是标准 :00000001FF", MD.ihex_eof() == ":00000001FF")
    check("C9 resume_size 对不存在的文件返回 0",
          MD.resume_size(os.path.join(tmpdir(), "nope.bin")) == 0)

    d = tmpdir()
    p = os.path.join(d, "a.bin")
    mem = {0x20000000 + i: (i * 7) & 0xFF for i in range(300)}

    def fake_read(addr, n):
        out = bytearray()
        for a in range(addr, addr + n):
            out.append(mem.get(a, 0xEE))
        return bytes(out)

    r = MD.dump(fake_read, 0x20000000, 300, p, "bin", chunk=64)
    check("C10 bin 转储成功且字节完全一致",
          r["ok"] and open(p, "rb").read() == bytes(mem[i] for i in sorted(mem)), r)
    check("C11 返回 sha256 / 吞吐 / 文件大小 / complete",
          r["complete"] is True and len(r["sha256"]) == 64
          and r["file_size"] == 300 and r["gap_count"] == 0, r)
    check("C12 bin 的 sha256 只覆盖本次写入字节（scope 说清）",
          "本次写入的 300 字节" in r["sha256_scope"], r.get("sha256_scope"))

    r = MD.dump(fake_read, 0x20000000, 300, p, "bin", chunk=64)
    check("C13 同名文件默认拒绝覆盖", r["ok"] is False and "已存在" in r["error"], r)
    r = MD.dump(fake_read, 0x20000000, 300, p, "bin", chunk=64, overwrite=True)
    check("C14 overwrite=true 可覆盖", r["ok"] is True, r)

    # 续传：先只要一半，再续到 300
    p2 = os.path.join(d, "r.bin")
    r1 = MD.dump(fake_read, 0x20000000, 150, p2, "bin", chunk=64)
    r2 = MD.dump(fake_read, 0x20000000, 300, p2, "bin", chunk=64, resume=True)
    check("C15 续传从已有长度起写（start_offset=150）",
          r1["ok"] and r2["ok"] and r2["start_offset"] == 150
          and r2["resumed"] is True, (r1.get("start_offset"), r2))
    check("C16 续传后文件长度等于 size 且内容逐字节正确",
          r2["file_size"] == 300
          and open(p2, "rb").read() == bytes(mem[i] for i in sorted(mem)), r2)
    r3 = MD.dump(fake_read, 0x20000000, 300, p2, "bin", resume=True)
    check("C17 已有文件不小于 size 时拒绝续传并说明", r3["ok"] is False
          and "无需续传" in r3["error"], r3)
    r4 = MD.dump(fake_read, 0x20000000, 40, os.path.join(d, "x.hex"), "ihex",
                 resume=True)
    check("C18 ihex 拒绝 resume（文本长度 ≠ 已读字节数）",
          r4["ok"] is False and "只支持 bin" in r4["error"], r4)

    # gaps：从 0x20000100 起读会抛异常
    def bad_read(addr, n):
        if addr >= 0x20000100:
            raise IOError("UVSOCK read timeout")
        return fake_read(addr, n)

    p3 = os.path.join(d, "g.bin")
    g = MD.dump(bad_read, 0x20000000, 300, p3, "bin", chunk=64, fill=0x00)
    check("C19 块读失败不放弃整段：complete=false 且记 gaps",
          g["ok"] and g["complete"] is False and g["gap_count"] >= 1
          and g["gaps"][0]["reason"], g.get("gaps"))
    check("C20 失败块按 gap_fill 补齐（fill=0x00）",
          open(p3, "rb").read()[0x100:0x110] == b"\x00" * 16, None)
    check("C21 有 gaps 时给 warning 说明补齐字节不是真实内容",
          "不是目标真实内容" in g.get("warning", ""), g.get("warning"))

    p4 = os.path.join(d, "h.hex")
    h = MD.dump(bad_read, 0x20000000, 300, p4, "ihex", chunk=64)
    txt = open(p4, "r", encoding="ascii").read().splitlines()
    check("C22 ihex 末尾有 EOF 且每行校验和自洽",
          txt[-1] == ":00000001FF" and all(_ihex_ok(l) for l in txt[:-1]), txt[-1])
    check("C23 ihex 转储也照样记 gaps（不因格式不同就假装完整）",
          h["complete"] is False and h["gap_count"] >= 1, h)

    p5 = os.path.join(d, "d.txt")
    hd = MD.dump(fake_read, 0x20000000, 32, p5, "hexdump")
    check("C24 hexdump 带地址列与 ASCII 列",
          "20000000  " in open(p5, encoding="utf-8").read(), None)

    check("C25 未知 format 被拒", MD.dump(fake_read, 0, 16, os.path.join(d, "z"),
                                     "elf")["ok"] is False)
    check("C26 size<=0 被拒", MD.dump(fake_read, 0, 0, os.path.join(d, "z"))["ok"] is False)
    r = MD.dump(fake_read, 0, MD.MAX_BYTES_DEFAULT + 1, os.path.join(d, "z"))
    check("C27 超过单次上限被拒并建议分批",
          r["ok"] is False and "上限" in r["error"], r)
    check("C28 缺 path 被拒", MD.dump(fake_read, 0, 16, "")["ok"] is False)

# ---------------------------------------------------------------------------
# D pointmap
# ---------------------------------------------------------------------------
def section_d():
    print("\nD pointmap：五档分类 / 引用号 / analyze 点表 / run 采样")
    c = PM.classify([5, 5, 5, 5])
    check("D1 全程同值 → constant",
          c["class"] == "constant" and c["changes"] == 0, c)
    c = PM.classify([0, 1, 1, 0])
    check("D2 只在 0/1 跳 → bistable", c["class"] == "bistable", c)
    c = PM.classify([10, 11, 12, 13])
    check("D3 单调增 → drifting（并说清方向与首末值）",
          c["class"] == "drifting" and "递增" in c["note"], c)
    c = PM.classify([9, 3, 7, 1])
    check("D4 无规律 → changing", c["class"] == "changing", c)
    c = PM.classify([None, None, None])
    check("D5 全无应答 → no_response 且明确「不代表是 0」",
          c["class"] == "no_response" and "不代表" in c["note"], c)
    c = PM.classify([None, 7, None, 7])
    check("D6 部分失败只按有效样本判（但仍报 ok_samples）",
          c["class"] == "constant" and c["ok_samples"] == 2, c)
    c = PM.classify([2, 2, 3])
    check("D7 distinct/span/changes 统计正确",
          c["distinct_count"] == 2 and c["span"] == 1 and c["changes"] == 1, c)

    check("D8 功能码 → 点类型映射",
          (PM.kind_of_func(1), PM.kind_of_func(2), PM.kind_of_func(3),
           PM.kind_of_func(4)) == ("coil", "discrete_input",
                                   "holding_register", "input_register"))
    check("D9 引用号按惯例给出（holding 4xxxx 从 1 起）",
          PM.ref_label("holding_register", 0) == "40001"
          and PM.ref_label("input_register", 9) == "30010", None)
    check("D10 线圈/离散输入引用号前缀 0/1",
          PM.ref_label("coil", 0) == "00001"
          and PM.ref_label("discrete_input", 0) == "10001", None)

    series = [[100, 0, 25, 7], [100, 1, 26, 7], [100, 1, 27, 7], [100, 0, 28, 7]]
    a = PM.analyze(series, 100, "holding_register")
    check("D11 analyze 每点都带地址/引用号/unconfirmed 语义标记",
          a["ok"] and a["points"][0]["address"] == "0x0064"
          and a["points"][0]["ref"] == "40101"
          and all(p["semantic_source"] == "unconfirmed" for p in a["points"]), a["points"][0])
    check("D12 summary 五档计数正确",
          (a["summary"]["constant"], a["summary"]["bistable"],
           a["summary"]["drifting"], a["summary"]["changing"],
           a["summary"]["no_response"]) == (2, 1, 1, 0, 0), a["summary"])
    check("D13 point_table 只收常量点（供直接当点表用）",
          [r["ref"] for r in a["point_table"]] == ["40101", "40104"], a["point_table"])
    check("D14 history 可选（include_history=False 时不给）",
          "history" not in PM.analyze(series, 100, "holding_register",
                                     include_history=False)["points"][0], None)
    check("D15 空采样/全失败时 ok=false 并给下一步提示",
          PM.analyze([], 0, "holding_register")["ok"] is False
          and PM.analyze([None, None], 0, "holding_register")["ok"] is False, None)

    calls = []

    def sampler(slave, func, addr, count):
        calls.append((slave, func, addr, count))
        if len(calls) == 3:
            raise RuntimeError("从站回异常帧 0x02")
        return [7, 300, 1]

    r = PM.run(sampler, slave=2, func=3, addr=10, count=3, samples=4,
               interval_ms=0, sleep=lambda s: None)
    check("D16 run 按 samples 次采样并把失败样本记进 sample_errors",
          len(calls) == 4 and r["sample_error_count"] == 1
          and r["sample_errors"][0]["error"].startswith("从站回异常帧"), r)
    check("D17 失败样本不污染分类（仍按有效样本判 constant）",
          r["summary"]["constant"] == 3, r["summary"])
    check("D18 run 带回 slave/func/samples_requested/interval_ms",
          (r["slave"], r["func"], r["samples_requested"], r["interval_ms"])
          == (2, 3, 4, 0), {k: r[k] for k in ("slave", "func", "samples_requested")})
    r2 = PM.run(sampler, 1, 3, 0, 1, samples=1, interval_ms=0, sleep=lambda s: None)
    check("D19 samples 被夹到 [2, 64]（1 → 2）", r2["samples_requested"] == 2,
          r2.get("samples_requested"))

# ---------------------------------------------------------------------------
# E 零依赖与文档 / 版本闸门
# ---------------------------------------------------------------------------
def section_e():
    print("\nE 零依赖与文档 / 版本闸门")
    for mod in ("writevar", "memdump", "pointmap"):
        src = open(os.path.join(ROOT, "mdkdebug", mod + ".py"), encoding="utf-8").read()
        mods = re.findall(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", src, re.M)
        third = [m for m in mods
                 if m.split(".")[0] not in ("os", "re", "struct", "sys", "json",
                                            "math", "time", "hashlib", "numparse",
                                            "__future__")]
        check("E1 %s.py 只依赖标准库与本仓库模块" % mod, third == [], third)
    src = open(os.path.join(ROOT, "mdkdebug", "writevar.py"), encoding="utf-8").read()
    check("E2 writevar 不 import UVSOCK / 不写文件（纯计算）",
          "import uvsock" not in src and "from .uvsock" not in src
          and not re.search(r"open\([^)]*['\"][wa]", src))
    src = open(os.path.join(ROOT, "mdkdebug", "memdump.py"), encoding="utf-8").read()
    check("E3 memdump 不 import uvsock / socket / serial（只依赖 read 回调）",
          not re.search(r"^\s*(?:from|import)\s+\S*uvsock", src, re.M)
          and not re.search(r"^\s*(?:from|import)\s+(socket|serial)", src, re.M))

    rd = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    check("E4 README 有批次106 的说明块", "批次106" in rd,
          re.findall(r"批次1\d\d", rd)[-6:])
    check("E5 README 三个新工具都出现在工具表里",
          all(("`%s`" % n) in rd for n in NEW_TOOLS),
          [n for n in NEW_TOOLS if ("`%s`" % n) not in rd])
    from mdkdebug import __version__ as V
    check("E6 README 目录树版本号与包一致",
          ("版本号 %s" % V) in rd, (V, re.findall(r"版本号 0\.2\.\d+", rd)))
    py = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    check("E7 版本三处同步（__init__ / pyproject / README）",
          ('version = "%s"' % V) in py and ("版本号 %s" % V) in rd, (V,))
    rt = open(os.path.join(ROOT, "tools", "run_all_tests.py"), encoding="utf-8").read()
    check("E8 全量闸门里含 test_batch106", '"test_batch106"' in rt)

def main():
    print("批次106 测试：写变量 / 区间转储 / Modbus 点表")
    for fn in (section_a, section_b, section_c, section_d, section_e):
        try:
            fn()
        except Exception as e:               # noqa: BLE001
            import traceback
            traceback.print_exc()
            FAIL.append("%s 抛异常：%s" % (fn.__name__, e))
    for d in TMP:
        shutil.rmtree(d, ignore_errors=True)
    print("\n%d pass / %d fail" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for x in FAIL:
            print("  -", x)
        return 1
    print("全部通过")
    return 0

if __name__ == "__main__":
    sys.exit(main())
