#! /usr/bin/env python3

import atheris
import sys

with atheris.instrument_imports():
    import hwilib._bech32 as segwit_addr

def TestBech32(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  hrp = fdp.ConsumeString(2)
  witver = fdp.ConsumeIntInRange(0, 20)
  witprog = fdp.ConsumeBytes(10000)
  addr = segwit_addr.encode(hrp, witver, witprog)
  if addr:
    addr_decoded = segwit_addr.decode(hrp, addr)
    assert addr_decoded[0] == witver

atheris.Setup(sys.argv, TestBech32)
atheris.Fuzz()