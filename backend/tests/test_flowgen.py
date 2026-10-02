"""The IPFIX generator's optional CTS group tags (enterprise elements), as GoFlow2 maps them."""

import struct
import sys
from pathlib import Path

SIM = Path(__file__).resolve().parents[2] / "simulators"
sys.path[:0] = [str(SIM / "flowgen"), str(SIM / "ise_sim")]

import flowgen  # noqa: E402
import ise_sim  # noqa: E402


def test_template_declares_cisco_sgt_enterprise_elements():
    plain = flowgen.template_set(sgt=False)
    tagged = flowgen.template_set(sgt=True)
    assert struct.unpack("!HHHH", tagged[:8])[2:] == (flowgen.TEMPLATE_ID, len(flowgen.FIELDS) + 2)
    # Each enterprise specifier: id with the enterprise bit (34000 = 0x8000 | 1232), length, PEN.
    tail = tagged[len(plain):]
    assert struct.unpack("!HHIHHI", tail) == (34000, 2, 9, 34001, 2, 9)
    assert 34000 & 0x7FFF == 1232  # what deploy/goflow2/mapping.yaml maps for IPFIX


def test_tags_match_the_ise_simulator():
    values = dict(ise_sim.SGTS)
    for sgt, (octet, lo, _) in ise_sim.CLIENT_NETS.items():
        assert flowgen.tag_of(f"10.10.{octet}.{lo}") == values[sgt]
    for sgt, net in ise_sim.SERVER_NETS.items():
        assert flowgen.tag_of(net.replace("0/24", "20")) == values[sgt]
    assert flowgen.tag_of("203.0.113.45") == 0
