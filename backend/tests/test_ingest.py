import json
import os

import pytest

from matrix_advisor.agent.llm import PrivacyViolation, assert_no_ip
from matrix_advisor.ingest.goflow import ExporterFilter, NDJSONTailer, orient, parse_record
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
    assert r.resolve("10.99.0.1") == "Unknown"
    assert r.resolve("198.51.100.7") == "Internet"


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
