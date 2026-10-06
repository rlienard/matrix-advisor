import json
import os

import pytest

from matrix_advisor.agent.llm import PrivacyViolation, assert_no_ip
from matrix_advisor.config import ConfigStore
from matrix_advisor.ingest.goflow import ExporterFilter, NDJSONTailer, decode_records, orient, parse_record
from matrix_advisor.ingest.pipeline import IngestPipeline
from matrix_advisor.ingest.resolver import SGTResolver


def test_orientation_folds_replies_onto_requests():
    assert orient("TCP", "10.20.1.5", 443, "10.10.1.7", 51000) == ("10.10.1.7", 51000, "10.20.1.5", 443)
    assert orient("TCP", "10.10.1.7", 51000, "10.20.1.5", 443) == ("10.10.1.7", 51000, "10.20.1.5", 443)
    assert orient("TCP", "10.20.4.5", 1433, "10.10.2.7", 50000)[3] == 1433
    assert orient("ICMP", "a", 0, "b", 0) == ("a", 0, "b", 0)


def test_parse_goflow2_v2_record():
    rec = {"type": "IPFIX", "time_flow_end_ns": 1_790_000_000_000_000_000, "sampler_address": "10.0.0.1",
           "src_addr": "10.20.1.5", "dst_addr": "10.10.1.7", "proto": "TCP", "src_port": 443, "dst_port": 51000,
           "bytes": 100, "packets": 2, "sampling_rate": 0}
    f = parse_record(json.dumps(rec).encode())
    assert (f.src_ip, f.dst_ip, f.dst_port, f.proto, f.bytes) == ("10.10.1.7", "10.20.1.5", 443, "TCP", 100)
    assert parse_record(b"not json") is None
    assert parse_record(json.dumps({**rec, "proto": 17}).encode()).proto == "UDP"


def test_decode_records_splits_concatenated_lines():
    assert decode_records(b'{"a":1}') == ([{"a": 1}], 0)
    # GoFlow2's file transport sometimes writes two records with no newline between them.
    assert decode_records(b'{"a":1}{"b":2} {"c":3}') == ([{"a": 1}, {"b": 2}, {"c": 3}], 0)
    # Records before an unparsable tail are kept; the tail counts as malformed.
    assert decode_records(b'{"a":1}{"b":') == ([{"a": 1}], 1)
    assert decode_records(b"not json") == ([], 1)
    assert decode_records(b"\xff{}") == ([], 1)


def test_tailer_handles_partial_lines_and_truncation(tmp_path):
    p = tmp_path / "flows.ndjson"
    p.write_bytes(b'{"a":1}\n{"b":')
    t = NDJSONTailer(str(p))
    assert t.read() == [b'{"a":1}']
    with open(p, "ab") as fh:
        fh.write(b'2}\n')
    assert t.read() == [b'{"b":2}']
    p.write_bytes(b'{"c":3}\n')  # truncated and rewritten
    assert t.read() == [b'{"c":3}']


def test_tailer_truncates_when_large(tmp_path):
    p = tmp_path / "flows.ndjson"
    p.write_bytes(b'{"a":1}\n' * 10)
    t = NDJSONTailer(str(p), max_bytes=20)
    assert len(t.read()) == 10
    assert os.path.getsize(p) == 0


def test_resolver_priorities():
    r = SGTResolver()
    r.set_static({"10.20.0.0/16": "Servers"})
    r.set_bindings({"10.20.1.0/24": "Web"})
    r.set_sessions({"10.20.1.9": "Employees"})
    assert r.resolve("10.20.1.9") == "Employees"
    assert r.resolve("10.20.1.10") == "Web"
    assert r.resolve("10.20.9.1") == "Servers"
    # Anything unclassified is SGT 0, internal or Internet alike: what the switch enforces on.
    assert r.resolve("10.99.0.1") == "Unknown"
    assert r.resolve("198.51.100.7") == "Unknown"
    r.set_tags({0: "Unknown_SGT0", 4: "Employees"})
    assert r.resolve("198.51.100.8") == "Unknown_SGT0"


def test_exporter_filter():
    f = ExporterFilter(["10.0.0.0/8"])
    assert f.allowed("10.1.2.3") and not f.allowed("192.168.1.1") and not f.allowed("")
    assert ExporterFilter([]).allowed("1.2.3.4")


def test_llm_payload_guard():
    assert_no_ip('{"src": "Employees", "port": "TCP/443", "first_seen": "2026-10-02T15:04:00"}')
    with pytest.raises(PrivacyViolation):
        assert_no_ip('{"host": "10.10.1.7"}')
    with pytest.raises(PrivacyViolation):
        assert_no_ip("fe80::1 talked")


def test_parse_record_with_sgt_tags():
    rec = {"type": "IPFIX", "time_flow_end_ns": 1_790_000_000_000_000_000, "sampler_address": "10.0.0.1",
           "src_addr": "10.10.1.7", "dst_addr": "10.20.1.5", "proto": "TCP", "src_port": 51000, "dst_port": 443,
           "bytes": 100, "packets": 2, "src_sgt": 4, "dst_sgt": 10}
    f = parse_record(json.dumps(rec).encode())
    assert (f.src_tag, f.dst_tag) == (4, 10)
    # A reply (server -> client) is folded onto the request: the tags are swapped with the addresses.
    reply = {**rec, "src_addr": "10.20.1.5", "dst_addr": "10.10.1.7", "src_port": 443, "dst_port": 51000,
             "src_sgt": 10, "dst_sgt": 4}
    f = parse_record(json.dumps(reply).encode())
    assert (f.src_ip, f.src_tag, f.dst_ip, f.dst_tag) == ("10.10.1.7", 4, "10.20.1.5", 10)
    # 0 is "unknown" in CTS fields; missing or garbage values are ignored.
    f = parse_record(json.dumps({**rec, "src_sgt": 0, "dst_sgt": "x"}).encode())
    assert (f.src_tag, f.dst_tag) == (None, None)
    assert parse_record(json.dumps({k: v for k, v in rec.items() if "sgt" not in k}).encode()).src_tag is None


class _Store:
    def __init__(self):
        self.rows = []

    def ingest(self, rows):
        self.rows += rows
        return len(rows)

    def flush_parquet(self):
        return None

    def compact(self):
        pass

    def rollup_daily(self, day=None):
        pass

    def apply_retention(self, days):
        pass


def _pipeline(tmp_path, sgt_source):
    flows = tmp_path / "flows.ndjson"
    base = {"type": "IPFIX", "time_flow_end_ns": 1_790_000_000_000_000_000, "sampler_address": "10.0.0.1",
            "proto": "TCP", "src_port": 51000, "dst_port": 443, "bytes": 100, "packets": 2}
    records = [
        # tags known to ISE win over IP resolution (the pxGrid session says Contractors)
        {**base, "src_addr": "10.10.1.7", "dst_addr": "10.20.1.5", "src_sgt": 4, "dst_sgt": 10},
        # unknown tag value: fall back to the address; tag 0 (Internet side): address as well
        {**base, "src_addr": "10.10.1.8", "dst_addr": "198.51.100.7", "src_sgt": 99, "dst_sgt": 0},
        # no tags at all
        {**base, "src_addr": "10.10.1.9", "dst_addr": "10.20.1.5"},
    ]
    flows.write_text("".join(json.dumps(r) + "\n" for r in records))
    (tmp_path / "config.yaml").write_text(
        f"collector: {{input_file: {flows}, allowed_exporters: [], sgt_source: {sgt_source}}}\n")
    resolver = SGTResolver()
    resolver.set_sessions({"10.10.1.7": "Contractors", "10.10.1.8": "Employees", "10.10.1.9": "Employees"})
    resolver.set_bindings({"10.20.1.0/24": "Web_Servers"})
    resolver.set_tags({4: "Employees", 10: "Web_Servers"})
    store = _Store()
    pipeline = IngestPipeline(ConfigStore(tmp_path / "config.yaml"), store, resolver)
    assert pipeline.tick() == 3
    return pipeline, [(r[2], r[9], r[4], r[10]) for r in store.rows]


def test_pipeline_prefers_sgt_from_flow_records(tmp_path):
    pipeline, rows = _pipeline(tmp_path, "auto")
    assert rows == [
        ("10.10.1.7", "Employees", "10.20.1.5", "Web_Servers"),
        ("10.10.1.8", "Employees", "198.51.100.7", "Unknown"),
        ("10.10.1.9", "Employees", "10.20.1.5", "Web_Servers"),
    ]
    assert (pipeline.stats["sgt_from_flow"], pipeline.stats["unknown_tag"]) == (2, 1)


def test_pipeline_ignores_tags_when_sgt_source_is_ip(tmp_path):
    pipeline, rows = _pipeline(tmp_path, "ip")
    assert rows[0][1] == "Contractors"
    assert (pipeline.stats["sgt_from_flow"], pipeline.stats["unknown_tag"]) == (0, 0)


def test_pipeline_keeps_flows_from_concatenated_lines(tmp_path):
    flows = tmp_path / "flows.ndjson"
    base = {"type": "IPFIX", "time_flow_end_ns": 1_790_000_000_000_000_000, "sampler_address": "10.0.0.1",
            "proto": "TCP", "src_port": 51000, "dst_port": 443, "bytes": 100, "packets": 2,
            "dst_addr": "10.20.1.5"}
    a, b, c = ({**base, "src_addr": f"10.10.1.{i}"} for i in (7, 8, 9))
    flows.write_text(json.dumps(a) + json.dumps(b) + "\n" + json.dumps(c) + "{\"broken\n" + "[1]\n")
    (tmp_path / "config.yaml").write_text(f"collector: {{input_file: {flows}, allowed_exporters: []}}\n")
    store = _Store()
    pipeline = IngestPipeline(ConfigStore(tmp_path / "config.yaml"), store, SGTResolver())
    assert pipeline.tick() == 3
    assert [r[2] for r in store.rows] == ["10.10.1.7", "10.10.1.8", "10.10.1.9"]
    assert pipeline.stats["concatenated_lines"] == 1
    assert pipeline.stats["malformed"] == 2  # the broken tail and the non-object record


def test_resolver_longest_prefix_and_ipv6():
    r = SGTResolver()
    r.set_bindings({"10.0.0.0/8": "Campus", "10.20.0.0/16": "Servers", "10.20.1.128/25": "Web",
                    "2001:db8::/32": "V6", "2001:db8:1::/48": "V6_Web", "bad": "x"})
    assert [r.resolve(ip) for ip in ("10.20.1.200", "10.20.1.5", "10.9.9.9", "11.0.0.1")] == \
        ["Web", "Servers", "Campus", "Unknown"]
    assert (r.resolve("2001:db8:1::5"), r.resolve("2001:db8:2::5")) == ("V6_Web", "V6")
    assert r.counts()["bindings"] == 5


def test_session_event_invalidates_only_the_addresses_it_names():
    r = SGTResolver()
    r.set_static({"10.1.0.0/16": "Employees"})
    r.set_tags({0: "Unknown"})
    for ip in ("10.1.0.1", "10.1.0.2", "10.9.0.1"):
        r.resolve(ip)
    r.update_sessions({"10.1.0.1": "Contractors"}, removed=["10.1.0.2"])
    assert set(r._cache) == {"10.9.0.1"}
    assert r.resolve("10.1.0.1") == "Contractors" and r.resolve("10.1.0.2") == "Employees"
    # SGT 0 renamed in ISE: cached unclassified addresses follow.
    r.set_tags({0: "Unknown_SGT0"})
    assert r.resolve("10.9.0.1") == "Unknown_SGT0"
