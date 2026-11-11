# -*- coding: utf-8 -*-
"""Modbus 点表探测（批次106）：多采几次，分清「常量 / 状态位 / 会变 / 无应答」。

为什么需要它
------------
`modbus_read` 只给**一次**读数。拿到 16 个寄存器的值时，人真正想知道的是：
哪些是固定参数（量程/地址/版本），哪些是实时量（温度/流量），哪些是一个 0/1 状态位，
哪些地址这片从站根本没实现。这些信息不在一次读数里，而在**同一批地址的多次采样**里。

本模块做三件事，都不碰串口（采样回调由 server 注入，便于单测）：

  classify   一组时序值 → 常量 / 双态 / 单调漂移 / 无规律变化 / 无应答
  analyze    多点 × 多采样 → 每点的分类、取值域、变化次数，并给「点表」候选
  run        按 interval_ms 采样 samples 次，再交给 analyze

**不猜语义**：分类只描述「读到的数怎么变」，不替你判定「这就是流量」。
寄存器地址按 Modbus 惯例给出 4xxxx/3xxxx/0xxxx/1xxxx 引用号，那只是**惯例标注**，
真正的语义必须由设备手册确认——所以每条都带 `semantic_source: "unconfirmed"`。
"""
from __future__ import annotations

import time

KIND_BY_FUNC = {
    1: "coil",
    2: "discrete_input",
    3: "holding_register",
    4: "input_register",
}
# Modbus 惯例引用号前缀：0xxxx 线圈、1xxxx 离散输入、3xxxx 输入寄存器、4xxxx 保持寄存器
REF_PREFIX = {
    "coil": "0",
    "discrete_input": "1",
    "holding_register": "4",
    "input_register": "3",
}
KIND_CN = {
    "coil": "线圈",
    "discrete_input": "离散输入",
    "holding_register": "保持寄存器",
    "input_register": "输入寄存器",
}


def kind_of_func(func) -> str:
    return KIND_BY_FUNC.get(int(func or 3), "holding_register")


def ref_label(kind: str, addr: int) -> str:
    """按惯例给出引用号（4xxxx / 3xxxx / 0xxxx / 1xxxx）。仅作标注。"""
    pre = REF_PREFIX.get(kind, "4")
    return "%s%04d" % (pre, int(addr) + 1)


def _uniq(values, limit: int = 8) -> list:
    seen, out = set(), []
    for v in values:
        if v is None or v in seen:
            continue
        seen.add(v)
        out.append(v)
        if len(out) >= limit:
            break
    return out


def classify(values) -> dict:
    """一组时序值 → 分类。values 里的 None 表示该次采样失败（不是「读到 0」）。"""
    ok = [v for v in (values or []) if v is not None]
    n_all = len(values or [])
    d = {"samples": n_all, "ok_samples": len(ok)}
    if not ok:
        d.update({"class": "no_response",
                  "note": "这 %d 次采样全都没有有效应答（超时/异常帧/越界），"
                          "不代表这个地址是 0" % n_all})
        return d
    d["value"] = ok[-1]
    d["min"] = min(ok)
    d["max"] = max(ok)
    d["span"] = d["max"] - d["min"]
    d["distinct"] = _uniq(ok)
    d["distinct_count"] = len({v for v in ok})
    changes = sum(1 for a, b in zip(ok, ok[1:]) if a != b)
    d["changes"] = changes
    if d["distinct_count"] == 1:
        d["class"] = "constant"
        d["note"] = "全程只有一个值，像是固定参数（量程/地址/版本/配置）"
        return d
    if set(ok) <= {0, 1}:
        d["class"] = "bistable"
        d["note"] = ("只在 0/1 之间跳变，很可能是一个状态位/开关量；"
                     "但寄存器里的 0/1 也可能是别的东西，需手册确认")
        return d
    inc = all(b >= a for a, b in zip(ok, ok[1:])) and d["span"] > 0
    dec = all(b <= a for a, b in zip(ok, ok[1:])) and d["span"] > 0
    if inc or dec:
        d["class"] = "drifting"
        d["note"] = ("%s变化（%d → %d），跨采样单调；像是实时量（温度/液位/计数）"
                     % ("递增" if inc else "递减", ok[0], ok[-1]))
        return d
    d["class"] = "changing"
    d["note"] = "多次采样之间无规律变化，可能是噪声/实时量/多寄存器拼成的 32 位量"
    return d


def analyze(series, base_addr: int, kind: str, include_history: bool = True,
            history_limit: int = 32) -> dict:
    """series 是「每次采样的一组值」的列表：[[v0,v1,…], None, …]。"""
    series = list(series or [])
    if not series:
        return {"ok": False, "error": "没有任何采样结果"}
    widths = [len(s) for s in series if isinstance(s, (list, tuple))]
    count = max(widths) if widths else 0
    if count <= 0:
        return {"ok": False, "error": "每次采样都没取到值（全部无应答）",
                "hint": "先用 modbus_read 单读一次确认从站在线、功能码/地址正确"}
    points = []
    for i in range(count):
        vals = []
        for s in series:
            if isinstance(s, (list, tuple)) and i < len(s):
                vals.append(s[i])
            else:
                vals.append(None)
        c = classify(vals)
        addr = int(base_addr) + i
        ent = {"index": i, "address": "0x%04X" % addr, "address_dec": addr,
               "ref": ref_label(kind, addr), "kind": kind,
               "semantic_source": "unconfirmed"}
        ent.update(c)
        if include_history:
            ent["history"] = (vals if len(vals) <= history_limit
                              else vals[:history_limit // 2] + ["…"] + vals[-history_limit // 2:])
        points.append(ent)
    stable = [p for p in points if p["class"] == "constant"]
    table = [{"ref": p["ref"], "address_dec": p["address_dec"],
              "kind": p["kind"], "value": p.get("value")} for p in stable]
    summary = {
        "points": len(points),
        "constant": len(stable),
        "bistable": len([p for p in points if p["class"] == "bistable"]),
        "drifting": len([p for p in points if p["class"] == "drifting"]),
        "changing": len([p for p in points if p["class"] == "changing"]),
        "no_response": len([p for p in points if p["class"] == "no_response"]),
        "samples": len(series),
    }
    out = {"ok": True, "kind": kind, "kind_cn": KIND_CN.get(kind, kind),
           "base_address": "0x%04X" % int(base_addr), "count": count,
           "summary": summary, "points": points,
           "point_table": table}
    if not stable and not any(p["class"] in ("bistable", "drifting", "changing")
                              for p in points):
        out["hint"] = ("全部地址都无有效应答——先确认从站号/接线/波特率/功能码；"
                       "越界地址在多数从站上会回异常帧 0x02")
    elif not stable:
        out["hint"] = "没有常量点：如果预期有固定参数，把 samples/interval_ms 调大再看"
    return out


def run(sampler, slave: int, func: int, addr: int, count: int, samples: int = 8,
        interval_ms: int = 200, include_history: bool = True,
        sleep=None) -> dict:
    """采样 samples 次（间隔 interval_ms），再分析。

    sampler(slave, func, addr, count) -> list[int]（失败请抛异常）。
    """
    samples = max(2, min(int(samples or 8), 64))
    interval_s = max(0.0, float(interval_ms or 0) / 1000.0)
    sleeper = sleep or time.sleep
    series, errors = [], []
    t0 = time.time()
    for i in range(samples):
        if i and interval_s:
            sleeper(interval_s)
        try:
            vals = sampler(slave, func, addr, count)
            series.append(list(vals) if isinstance(vals, (list, tuple)) else None)
        except Exception as e:  # noqa: BLE001
            series.append(None)
            errors.append({"sample": i, "error": str(e)})
    res = analyze(series, addr, kind_of_func(func),
                  include_history=include_history)
    res.update({"slave": int(slave), "func": int(func), "samples_requested": samples,
                "interval_ms": int(interval_ms),
                "elapsed_ms": int((time.time() - t0) * 1000)})
    if errors:
        res["sample_errors"] = errors[:10]
        res["sample_error_count"] = len(errors)
    return res
