import json

from gateways.ingress_metrics import parse, summarize


def test_live_tcp_rtt_and_deltas_do_not_expose_client_addresses():
    sockets = """0 0 [::ffff:38.60.203.137]:443 [::ffff:8.8.8.8]:50001
     cubic rtt:250.5/30.1 retrans:0/12 data_segs_out:400
0 0 38.60.203.137:8443 1.1.1.1:50002
     cubic rtt:450.2/21.5 retrans:0/4 data_segs_out:50
0 0 127.0.0.1:443 127.0.0.1:50003
     cubic rtt:0.1/0.1 retrans:0/0 data_segs_out:20
0 0 38.60.203.137:22 8.8.8.8:50004
     cubic rtt:80.0/0.1 retrans:0/0 data_segs_out:20
"""
    current = parse(sockets)
    assert len(current) == 2
    assert "8.8.8.8" not in json.dumps(current)
    assert "1.1.1.1" not in json.dumps(current)
    previous = {
        "checked_at": 100,
        "rows": {
            key: {**row, "retrans": row["retrans"] - 2, "segments": row["segments"] - 10}
            for key, row in current.items()
        },
    }
    result = summarize(current, previous, 160)
    assert result["ingress_rtt_median_ms"] == 350.4
    assert result["ingress_rtt_p95_ms"] == 450.2
    assert result["ingress_retrans_delta"] == 4
    assert result["ingress_data_segments_delta"] == 20
    assert result["ingress_sample_seconds"] == 60
    assert summarize(current, previous, 500)["ingress_retrans_delta"] is None
    assert summarize({}, previous, 160)["ingress_rtt_p95_ms"] is None
    assert summarize(current, {}, 160)["ingress_retrans_delta"] is None
