"""Flow aggregates: split tables, compaction, daily rollup, migration from the single per-minute table."""

from datetime import timedelta

import duckdb

from matrix_advisor.store import Store, utcnow


def _row(ts, src_ip, dst_ip, port, src="Employees", dst="Web_Servers", proto="TCP"):
    return (ts.strftime("%Y-%m-%d %H:%M:%S.%f"), "10.0.0.1", src_ip, 50000, dst_ip, port, proto, 100, 2, src, dst)


def _counts(store: Store) -> dict[str, int]:
    return {t: store.conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
            for t in ("pair_minutes", "host_daily", "host_minutes")}


def test_ingest_batches_aggregate_without_addresses_and_compact():
    store = Store(":memory:")
    now = utcnow().replace(second=0, microsecond=0) - timedelta(minutes=5)
    # Three batches of the same minute, as the 5 s ingest ticks write them; 20 hosts, 2 ports.
    for batch in range(3):
        store.ingest([_row(now + timedelta(seconds=batch), f"10.1.0.{h}", "10.2.0.1", port)
                      for h in range(20) for port in (443, 80)])
    ports = {p["port"]: p for p in store.pair_ports(now - timedelta(hours=1))}
    assert ports[443]["flows"] == 60 and ports[443]["hosts"] == 20
    assert store.pair_hosts(now - timedelta(hours=1)) == {("Employees", "Web_Servers"): 20}
    assert store.flow_rate(minutes=10) == 0.2  # 120 flows over 10 minutes
    before = _counts(store)
    assert before["pair_minutes"] == 6  # no address: one row per port and batch, not per host

    store.compact()
    assert _counts(store) == {"pair_minutes": 2, "host_daily": 40, "host_minutes": 20}
    assert {p["port"]: p for p in store.pair_ports(now - timedelta(hours=1))} == ports


def test_rollup_counts_hosts_per_day():
    store = Store(":memory:")
    day = utcnow() - timedelta(days=10)
    store.ingest([_row(day + timedelta(minutes=i), f"10.1.0.{i % 4}", "10.2.0.1", 22) for i in range(12)])
    store.rollup_daily(day)
    rows = store.conn.execute("SELECT flows, hosts FROM pair_daily").fetchall()
    assert rows == [(12, 4)]


def test_behaviour_detects_periodic_host_pairs():
    store = Store(":memory:")
    start = utcnow().replace(second=0, microsecond=0) - timedelta(hours=3)
    store.ingest([_row(start + timedelta(minutes=10 * i), "10.1.0.9", "10.2.0.1", 443) for i in range(10)])
    store.ingest([_row(start + timedelta(minutes=i * i), "10.1.0.8", "10.2.0.1", 443) for i in range(10)])
    b = store.pair_behaviour("Employees", "Web_Servers", start - timedelta(minutes=1))
    assert b["host_pairs"] == 2
    assert b["periodic_host_pairs"] == 1 and b["periodic_interval_s"] == 600


def test_legacy_flow_minutes_are_migrated(tmp_path):
    path = str(tmp_path / "legacy.duckdb")
    minute = (utcnow() - timedelta(hours=1)).replace(second=0, microsecond=0)
    conn = duckdb.connect(path)
    conn.execute("""CREATE TABLE flow_minutes (minute TIMESTAMP, src_sgt VARCHAR, dst_sgt VARCHAR, proto VARCHAR,
                    port INTEGER, src_ip VARCHAR, dst_ip VARCHAR, flows BIGINT, bytes BIGINT, packets BIGINT)""")
    conn.executemany("INSERT INTO flow_minutes VALUES (?, 'Employees', 'Web_Servers', 'TCP', 443, ?, '10.2.0.1', 2, 10, 1)",
                     [[minute, f"10.1.0.{h}"] for h in range(5)])
    conn.close()

    store = Store(path)
    tables = {r[0] for r in store.conn.execute("SELECT table_name FROM information_schema.tables").fetchall()}
    assert "flow_minutes" not in tables
    [port] = store.pair_ports(minute - timedelta(minutes=1))
    assert (port["flows"], port["bytes"], port["hosts"]) == (10, 50, 5)
    assert store.pair_behaviour("Employees", "Web_Servers", minute - timedelta(minutes=1))["host_pairs"] == 5
    store.close()
    Store(path).close()  # opening again is a no-op


def test_folding_host_minutes_keeps_behaviour_identical():
    import random

    random.seed(7)
    store = Store(":memory:")
    now = utcnow().replace(second=0, microsecond=0)
    start = now - timedelta(days=3)
    rows = []
    for i in range(3 * 24 * 4):  # every 15 minutes for 3 days: periodic, across midnights
        rows.append(_row(start + timedelta(minutes=15 * i), "10.1.0.9", "10.2.0.1", 443))
    for i in range(400):  # irregular host pair
        rows.append(_row(start + timedelta(minutes=random.randint(0, 3 * 24 * 60)), "10.1.0.8", "10.2.0.1", 443))
    for i in range(3):  # too few minutes to judge
        rows.append(_row(start + timedelta(hours=i), "10.1.0.7", "10.2.0.1", 443))
    store.ingest(rows)
    since = now - timedelta(days=7)
    expected = store.pair_behaviour("Employees", "Web_Servers", since)
    assert expected["host_pairs"] == 3 and expected["periodic_host_pairs"] == 1
    assert expected["periodic_interval_s"] == 900

    # Fold progressively, as compaction does every 10 minutes, then completely.
    for hours in [*range(72, 0, -7), 0]:
        store.fold_host_minutes(now - timedelta(hours=hours))
        assert store.pair_behaviour("Employees", "Web_Servers", since) == expected
    # Only the last half hour stays as minutes.
    assert store.conn.execute("SELECT min(minute) FROM host_minutes").fetchone()[0] >= now - timedelta(minutes=30)
    rows = store.conn.execute("SELECT count(*) FROM host_pair_daily").fetchone()[0]
    assert rows <= 3 * 4  # one row per address pair and day, not per active minute


def test_minutes_arriving_after_their_fold_are_left_out():
    store = Store(":memory:")
    now = utcnow().replace(second=0, microsecond=0)
    store.ingest([_row(now - timedelta(hours=2, minutes=10 * i), "10.1.0.9", "10.2.0.1", 443) for i in range(6)])
    assert store.fold_host_minutes(now) == 6
    late = now - timedelta(hours=3)
    store.ingest([_row(late, "10.1.0.9", "10.2.0.1", 443)])
    store.fold_host_minutes(now + timedelta(minutes=10))
    assert store.conn.execute("SELECT count(*) FROM host_minutes").fetchone()[0] == 0
    [(minutes,)] = store.conn.execute("SELECT sum(minutes) FROM host_pair_daily").fetchall()
    assert minutes == 6
    # Flow counts still include the late flow.
    assert store.pair_ports(now - timedelta(days=1))[0]["flows"] == 7
