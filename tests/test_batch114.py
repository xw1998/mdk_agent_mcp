# -*- coding: utf-8 -*-
"""批次114 测试：pyOCD 链路（pyocd_* 工具族 + 条件触发的读数源适配）。

要解决的问题：UVSOCK 只服务 Keil。没装 Keil、不想开 uVision、或者在无界面机器上，
调试/烧录/读内存都没有入口；OpenOCD 又要独占探针并常驻外部进程。pyOCD 是纯 Python
的第三条链路（进程内 Session），本批把它接进来。

分节：

  A 工具面与注解：注册 246、pyocd 15 个、不进默认面、只读/会改归类、check_surface
  B 参数校验：地址/数据/宽度/擦除/烧录/未连会话——一律明确错误码，不静默降级
  C 会话与读数语义（假目标）：open 的选项与错误、分块读、退化识别、
    running 两读不一致 → medium、写入回读校验
  D 工具端到端（假会话）：status/info/read/write/reg/bp/wp/control/list
  E 触发路由与文档：PyOCDMemoryClient 的 read_mem_verified 形状、不支持的方法报错、
    README/SKILL/版本/闸门登记、lean 档下描述关键句仍存活
  F 真机（可选，MDKDEBUG_PYOCD_HW=1 才跑）：列探针 + 连上读 CPUID

运行：python -m tests.test_batch114
"""
import ast
import asyncio
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MDKDEBUG_TOOLSETS", "all")

from mdkdebug import pyocdlink as P  # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=None):
    (PASS if ok else FAIL).append(name)
    print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name,
                            "" if ok else str(detail)[:500]), flush=True)


def _src(rel):
    return open(os.path.join(ROOT, rel), "rb").read().decode("utf-8")


def _call(server, name, args=None):
    async def _go():
        r = await server.call_tool(name, args or {})
        parts = [getattr(c, "text", "") for c in (getattr(r, "content", []) or [])]
        txt = "\n".join(p for p in parts if p)
        try:
            return json.loads(txt)
        except Exception:  # noqa: BLE001
            return {"_raw": txt}
    return asyncio.run(_go())


# ---------------------------------------------------------------------------
# 假目标 / 假会话：只实现 pyocdlink 真正用到的那几个方法
# ---------------------------------------------------------------------------
class FakeMem:
    def __init__(self, size=0x2000, base=0x20000000):
        self.base = base
        self.buf = bytearray(size)
        self.fail_at = None      # 在某个偏移抛出异常
        self.short_at = None     # 在某个偏移少返回字节
        self.script = []         # [(addr, bytes)] 依次替换读结果

    def read(self, addr, size):
        off = addr - self.base
        if off < 0 or off + size > len(self.buf):
            raise ValueError("out of range 0x%08X" % addr)
        if self.fail_at is not None and off >= self.fail_at:
            raise RuntimeError("transfer error")
        if self.script:
            a, data = self.script[0]
            if addr == a:
                self.script.pop(0)
                return list(data[:size])
        data = list(self.buf[off:off + size])
        if self.short_at is not None and off >= self.short_at:
            return data[:-1]
        return data

    def write(self, addr, data):
        off = addr - self.base
        if off < 0 or off + len(data) > len(self.buf):
            raise ValueError("out of range 0x%08X" % addr)
        self.buf[off:off + len(data)] = bytes(data)


class FakeRegs:
    def __init__(self):
        self.vals = {"r0": 0x11, "r1": 0x22, "pc": 0x08000100, "sp": 0x20001000,
                     "xpsr": 0x01000000}
        self.by_name = {k: k for k in ("r0", "r1", "r2", "r3", "sp", "lr", "pc", "xpsr")}

    def read(self, names):
        out = []
        for n in names:
            if n not in self.by_name:
                raise ValueError("no such register %s" % n)
            out.append(self.vals.get(str(n), 0))
        return out

    def write(self, names, data):
        for n, v in zip(names, data):
            self.vals[str(n)] = int(v)


class FakeTarget:
    def __init__(self, state="halted", mem=None):
        self.state = state
        self.mem = mem or FakeMem()
        self.regs = FakeRegs()
        self.core_registers = type("Idx", (), {"by_name": self.regs.by_name})()
        self.bps = set()
        self.wps = set()
        self.part_number = "STM32F401CC"
        self.vendor = "STMicroelectronics"
        self.name = "STM32F401CC"
        self.cores = [0]

    # 状态
    def get_state(self):
        return _Enum(self.state)

    def get_halt_reason(self):
        return _Enum("debug")

    def halt(self):
        self.state = "halted"

    def resume(self):
        self.state = "running"

    def reset(self, rt=None):
        self.state = "running"

    def reset_and_halt(self):
        self.state = "halted"

    def step(self, *a, **k):
        self.state = "halted"

    def init(self):
        pass

    # 内存
    def read_memory_block8(self, addr, size):
        return self.mem.read(addr, size)

    def write_memory_block8(self, addr, data):
        self.mem.write(addr, data)

    # 寄存器
    def read_core_registers_raw(self, names):
        return self.regs.read(list(names))

    def write_core_registers_raw(self, names, data):
        self.regs.write(list(names), list(data))

    # 断点 / 观察点
    def set_breakpoint(self, addr, kind=None):
        self.bps.add(int(addr))
        return True

    def remove_breakpoint(self, addr, kind=None):
        self.bps.discard(int(addr))

    def find_breakpoint(self, addr):
        return "bp" if int(addr) in self.bps else None

    def set_watchpoint(self, addr, size, kind):
        self.wps.add((int(addr), int(size)))
        return True

    def remove_watchpoint(self, addr, size, kind=None):
        self.wps.discard((int(addr), int(size)))

    # 内存映射
    def get_memory_map(self):
        r = type("R", (), {})
        r1 = r()
        r1.start, r1.end, r1.length = 0x08000000, 0x0803FFFF, 0x40000
        r1.type = "MemoryType.FLASH"
        r1.attributes = {"name": "FLASH"}
        r2 = r()
        r2.start, r2.end, r2.length = 0x20000000, 0x2000FFFF, 0x10000
        r2.type = "MemoryType.RAM"
        r2.attributes = {"name": "SRAM"}
        return type("MM", (), {"regions": [r1, r2]})()


class _Enum:
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name


class FakeProbe:
    unique_id = "FAKE-0001"
    description = "Fake CMSIS-DAP"
    vendor_name = "Fake"
    product_name = "Fake Probe"
    board_name = ""
    protocol = "swd"


class FakeSession:
    def __init__(self, target=None, is_open=True):
        self.target = target or FakeTarget()
        self.is_open = is_open
        self.probe = FakeProbe()
        self.closed = False

    def open(self):
        self.is_open = True

    def close(self):
        self.closed = True
        self.is_open = False


def _session(target=None, state="halted"):
    t = target or FakeTarget(state=state)
    if target is None:
        t.state = state
    s = P.PyOCDSession()
    s.sess = FakeSession(t)
    s.started_at = 0.0
    s.opts = {"connect_mode": "halt"}
    return s


# ---------------------------------------------------------------------------
# A 工具面与注解
# ---------------------------------------------------------------------------
def section_a(srv, names):
    from mdkdebug import toolbox as TB, annotate as AN
    py = sorted(n for n in names if n.startswith("pyocd_"))
    check("A1 注册 246 个工具，其中 pyocd_* 恰好 15 个",
          len(names) == 246 and len(py) == 15, "%d / %d" % (len(names), len(py)))
    check("A2 pyocd 组成员与注册的工具一一对应",
          set(py) == set(TB.TOOLSETS["pyocd"]), (set(py) ^ set(TB.TOOLSETS["pyocd"])))
    core = set(TB.TOOLSETS["core"]) | set(TB.ALWAYS)
    check("A3 pyocd 不进默认面（默认仍是 42 个）", len(core) == 42, len(core))
    check("A4 注解表完整覆盖且不重不漏：check_surface == []",
          AN.check_surface(names) == [], AN.check_surface(names))
    check("A5 pyocd_read_mem 只读、pyocd_write_mem 会改",
          ("pyocd_read_mem" in AN.READONLY) and ("pyocd_write_mem" in AN.MUTATING)
          and ("pyocd_read_mem" not in AN.MUTATING), None)
    check("A6 pyocd_start / pyocd_flash 是非幂等（同参数再来一次不是同一件事）",
          {"pyocd_start", "pyocd_flash", "pyocd_erase", "pyocd_gdb"} <= AN.NON_IDEMPOTENT,
          AN.NON_IDEMPOTENT & {"pyocd_start", "pyocd_flash"})


# ---------------------------------------------------------------------------
# B 参数校验（不依赖会话）
# ---------------------------------------------------------------------------
def section_b(srv):
    r = _call(srv, "pyocd_read_mem", {"addr": "0xZZZ"})
    check("B1 非法地址 → pyocd-bad-addr（不猜成 0）",
          (not r.get("ok")) and r.get("error_code") == "pyocd-bad-addr", r)
    r = _call(srv, "pyocd_write_mem", {"addr": "0x20000000"})
    check("B2 写内存既没 data_hex 也没 words → pyocd-no-data",
          (not r.get("ok")) and r.get("error_code") == "pyocd-no-data", r)
    r = _call(srv, "pyocd_write_mem", {"addr": "0x20000000", "data_hex": "ABC"})
    check("B3 奇数个十六进制字符 → pyocd-bad-data",
          (not r.get("ok")) and r.get("error_code") == "pyocd-bad-data", r)
    r = _call(srv, "pyocd_write_mem", {"addr": "0x20000000", "data_hex": "00", "width": 3})
    check("B4 width 只支持 1/2/4/8 → pyocd-bad-width",
          (not r.get("ok")) and r.get("error_code") == "pyocd-bad-width", r)
    r = _call(srv, "pyocd_flash", {"file": ""})
    check("B5 烧录没给文件 → pyocd-no-file",
          (not r.get("ok")) and r.get("error_code") == "pyocd-no-file", r)
    r = _call(srv, "pyocd_erase", {"mode": "sector"})
    check("B6 sector 擦除不给地址 → pyocd-no-erase-address",
          (not r.get("ok")) and r.get("error_code") == "pyocd-no-erase-address", r)
    r = _call(srv, "pyocd_control", {"action": "fly"})
    check("B7 未知运行控制动作 → pyocd-not-connected（先报没连，不假装动作存在）"
          if not P.get_session().running() else "B7 未知动作被拒",
          not r.get("ok"), r)
    r = _call(srv, "pyocd_reg", {"action": "write", "name": "pc"})
    check("B8 写寄存器缺 value → pyocd-reg-value-required",
          (not r.get("ok")) and r.get("error_code") == "pyocd-reg-value-required", r)


# ---------------------------------------------------------------------------
# C 会话与读数语义（假目标，直接测 PyOCDSession）
# ---------------------------------------------------------------------------
def section_c():
    s = P.PyOCDSession()
    try:
        s.target()
        ok = False
        code = ""
    except P.PyOCDError as e:
        ok = True
        code = e.code
    check("C1 未开会话时拿 target → pyocd-not-connected", ok and code == "pyocd-not-connected",
          code)

    # 分块读：跨越 MEM_CHUNK，内容必须逐字节吻合
    t = FakeTarget()
    for i in range(0x1200):
        t.mem.buf[i] = (i * 7 + 3) & 0xFF
    s = _session(t)
    data = s.read_bytes(0x20000000, 0x1200)
    check("C2 超过单块大小的读自动分块，内容逐字节吻合",
          data == bytes(t.mem.buf[:0x1200]), (len(data), data[:8]))

    # 短读必须报错，不能把缺的字节当 0
    t = FakeTarget()
    t.mem.short_at = 0
    s = _session(t)
    try:
        s.read_bytes(0x20000000, 8)
        code = ""
    except P.PyOCDError as e:
        code = e.code
    check("C3 读回的字节数不足 → pyocd-short-read（不补零糊过去）",
          code == "pyocd-short-read", code)

    # 退化：全 0 → low
    t = FakeTarget()
    s = _session(t)
    r = s.read_verified(0x20000000, 16)
    check("C4 连读都是整帧全 0 → read_confidence=low 且带 degenerate=all_zero",
          r.get("read_confidence") == "low" and r.get("degenerate") == "all_zero",
          {k: r.get(k) for k in ("read_confidence", "degenerate")})

    # Flash 区段全 FF 是预期内容，不能判 low
    t = FakeTarget()
    for i in range(16):
        t.mem.buf[i] = 0xFF
    s = _session(t)
    r = s.read_verified(0x20000000, 16)
    check("C5 SRAM 全 FF → low（不能当内容）",
          r.get("read_confidence") == "low" and r.get("degenerate") == "all_ff",
          r.get("read_confidence"))

    # running 两读不同 → medium + read_unstable，且两种解释都写进 warning
    t = FakeTarget(state="running")
    s = _session(t)
    t.mem.buf[0:4] = b"\x01\x02\x03\x04"
    t.mem.script = [(0x20000000, b"\x09\x09\x09\x09")]
    r = s.read_verified(0x20000000, 4)
    check("C6 目标 running 且两读不同 → medium + read_unstable（不下断言）",
          r.get("read_confidence") == "medium" and r.get("read_unstable") is True
          and r.get("reread_consistent") is False, r.get("read_confidence"))

    # halted 两读不同 → low（读数不可信）
    t = FakeTarget(state="halted")
    s = _session(t)
    t.mem.buf[0:4] = b"\x01\x02\x03\x04"
    t.mem.script = [(0x20000000, b"\x05\x05\x05\x05"), (0x20000000, b"\x06\x06\x06\x06")]
    r = s.read_verified(0x20000000, 4, verify="always")
    check("C7 目标 halted 且强制复读仍不一致 → low（明确不可信）",
          r.get("read_confidence") == "low" and r.get("reread_consistent") is False,
          r.get("read_confidence"))

    # 写回读校验
    t = FakeTarget()
    s = _session(t)
    s.write_bytes(0x20000010, b"\xAA\xBB")
    check("C8 写内存后内存里确实是那两个字节",
          bytes(t.mem.buf[0x10:0x12]) == b"\xAA\xBB", t.mem.buf[0x10:0x12])

    # open 的错误分流
    s = P.PyOCDSession()
    orig = P._pyocd
    class _CH:
        @staticmethod
        def session_with_chosen_probe(**_kw):
            return None
    P._pyocd = lambda: (object(), _CH)
    try:
        s.open()
        code = ""
    except P.PyOCDError as e:
        code = e.code
    finally:
        P._pyocd = orig
    check("C9 没有匹配的探针 → pyocd-no-probe（不抛裸异常）", code == "pyocd-no-probe", code)

    # 已开会话再 open → already-open
    s = _session()
    try:
        s.open()
        code = ""
    except P.PyOCDError as e:
        code = e.code
    check("C10 会话已开时再 open → pyocd-already-open", code == "pyocd-already-open", code)


# ---------------------------------------------------------------------------
# D 工具端到端（假会话注入到单例）
# ---------------------------------------------------------------------------
def section_d(srv):
    t = FakeTarget()
    t.mem.buf[0:8] = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    fake = _session(t)
    P._CACHE["sess"] = fake
    try:
        r = _call(srv, "pyocd_status")
        check("D1 pyocd_status 报 running / 目标 state / 断点数",
              r.get("running") is True and r.get("target", {}).get("state") == "halted"
              and r.get("breakpoints") == 0, r)

        r = _call(srv, "pyocd_info")
        mm = r.get("target", {}).get("memory_map") or []
        check("D2 pyocd_info 给出 part_number 与内存映射",
              r.get("target", {}).get("part_number") == "STM32F401CC" and len(mm) == 2, r)

        r = _call(srv, "pyocd_read_mem", {"addr": "0x20000000", "n_bytes": 8})
        check("D3 pyocd_read_mem 返回 data_hex/words/hexdump 且内容一致",
              r.get("data_hex") == "0102030405060708"
              and r.get("words", [""])[0] == "0x04030201"
              and len(r.get("hexdump") or []) == 1, r)

        r = _call(srv, "pyocd_write_mem", {"addr": "0x20000020", "data_hex": "de ad be ef"})
        check("D4 pyocd_write_mem 写完回读 verified=true",
              r.get("ok") and r.get("verified") is True and r.get("written") == 4, r)

        r = _call(srv, "pyocd_write_mem", {"addr": "0x20000030", "words": "1,2", "width": 2})
        check("D5 words+width 按小端写（1,2 → 01000200）",
              r.get("ok") and bytes(t.mem.buf[0x30:0x34]) == b"\x01\x00\x02\x00",
              bytes(t.mem.buf[0x30:0x34]))

        r = _call(srv, "pyocd_reg", {"action": "read", "names": "pc,sp"})
        check("D6 pyocd_reg 只读指定名字",
              r.get("registers") == {"pc": "0x08000100", "sp": "0x20001000"}, r)

        r = _call(srv, "pyocd_reg", {"action": "write", "name": "r0", "value": "0x99"})
        check("D7 pyocd_reg 写并回读",
              r.get("ok") and r.get("readback") == "0x00000099", r)

        r = _call(srv, "pyocd_bp", {"action": "set", "addr": "0x08000100"})
        r2 = _call(srv, "pyocd_bp", {"action": "list"})
        r3 = _call(srv, "pyocd_bp", {"action": "clear", "addr": "0x08000100"})
        check("D8 断点 set→list(1, present=true)→clear(0)",
              r.get("ok") and r2.get("count") == 1
              and r2["breakpoints"][0].get("present") is True and r3.get("ok"), (r, r2, r3))

        r = _call(srv, "pyocd_wp", {"action": "set", "addr": "0x20000000", "size": 4})
        r2 = _call(srv, "pyocd_wp", {"action": "list"})
        check("D9 观察点 set→list 记录 addr/size/kind",
              r.get("ok") and r2.get("count") == 1
              and r2["watchpoints"][0].get("size") == 4, (r, r2))

        r = _call(srv, "pyocd_control", {"action": "halt"})
        check("D10 pyocd_control(halt) 返回 state=halted 与 pc/sp",
              r.get("state") == "halted" and r.get("regs", {}).get("pc"), r)

        r = _call(srv, "pyocd_list")
        check("D11 pyocd_list 报 available.installed 与探针字段（不要求真探针）",
              r.get("available", {}).get("installed") is True
              and isinstance(r.get("probes"), list), r)

        # 读数源适配器：条件触发用的形状
        ad = P.PyOCDMemoryClient(P.get_session())
        rr = ad.read_mem_verified(0x20000000, 4)
        check("D12 PyOCDMemoryClient.read_mem_verified 给出触发需要的字段",
              rr.get("ok") and rr.get("data_hex") == "01020304"
              and rr.get("read_confidence") == "high" and "reread_consistent" in rr, rr)
        try:
            ad.calc_expression("x")
            code = ""
        except P.PyOCDError as e:
            code = e.code
        check("D13 适配器不提供 Keil 专有能力时明确报错（不返回空字典）",
              code == "pyocd-unsupported", code)
    finally:
        P._CACHE["sess"] = None


# ---------------------------------------------------------------------------
# E 文档 / 版本 / 闸门 / lean 描述
# ---------------------------------------------------------------------------
def section_e(srv):
    readme = _src("README.md")
    skill = _src("skills/mdkdebug/SKILL.md")
    check("E1 README 有 pyOCD 小节，SKILL 有 pyOCD 段",
          ("pyOCD" in readme or "pyocd" in readme) and "pyocd_start" in readme
          and "pyocd_start" in skill, None)
    init = _src("mdkdebug/__init__.py")
    pp = _src("pyproject.toml")
    check("E2 版本三处同步到 0.3.0",
          '__version__ = "0.3.0"' in init and 'version = "0.3.0"' in pp
          and "0.3.0" in readme, None)
    gat = _src("tools/run_all_tests.py")
    check("E3 tools/run_all_tests.py 已登记 test_batch114",
          "test_batch114" in gat, None)
    desc = {t.name: (getattr(t, "description", "") or "")
            for t in asyncio.run(srv.list_tools())}
    d = desc.get("pyocd_start", "")
    check("E4 lean 档下 pyocd_start 描述仍含「探针」与「pyOCD」（服务后描述）",
          ("探针" in d) and ("pyOCD" in d), "len=%d" % len(d))
    check("E5 pyocd_read_mem 描述写明「可信度」，pyocd_flash 写明「复位」",
          "可信度" in desc.get("pyocd_read_mem", "")
          and "复位" in desc.get("pyocd_flash", ""), None)
    # 预注册文档（吸收决策）必须入库
    doc = os.path.join(ROOT, "docs", "pyocd-link.md")
    check("E6 docs/pyocd-link.md 存在且有「不做什么」一节",
          os.path.exists(doc) and "不做" in open(doc, "rb").read().decode("utf-8"),
          None)
    # 语法自检：新增模块必须能被 ast 解析（防止写盘时混进坏字符）
    ast.parse(_src("mdkdebug/pyocdlink.py"))
    check("E7 mdkdebug/pyocdlink.py 可被 ast 解析", True, None)


# ---------------------------------------------------------------------------
# F 真机（可选）
# ---------------------------------------------------------------------------
def section_f(srv):
    if os.environ.get("MDKDEBUG_PYOCD_HW") != "1":
        check("F0 真机测试未启用（MDKDEBUG_PYOCD_HW=1 才跑）", True, None)
        return
    s = P.PyOCDSession()
    P._CACHE["sess"] = s
    try:
        r = s.open(connect_mode="attach")
        cpu = s.read_verified(0xE000ED00, 4)
        check("F1 真机连上 DAPLink 并读到 CPUID",
              r.get("ok") and cpu.get("ok") and cpu.get("read_confidence") == "high", cpu)
        st = s.control("halt")
        regs = s.read_regs(["pc", "sp"])
        s.control("resume")
        check("F2 真机 halt→读 pc/sp→resume 全通",
              st.get("state") == "halted" and regs.get("pc"), (st, regs))
    finally:
        s.close()
        P._CACHE["sess"] = None


def main():
    print("== 批次114：pyOCD 链路 ==")
    from mdkdebug import server as SV
    srv = SV.create_server(port=4823, toolsets="all")
    names = [t.name for t in asyncio.run(srv.list_tools())]
    for fn in (lambda: section_a(srv, names), lambda: section_b(srv),
               lambda: section_c(), lambda: section_d(srv),
               lambda: section_e(srv), lambda: section_f(srv)):
        fn()
    print("\n通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败：")
        for f in FAIL:
            print("  -", f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
