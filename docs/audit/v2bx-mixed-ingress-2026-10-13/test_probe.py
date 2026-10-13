import unittest,importlib.util
from unittest.mock import patch
from pathlib import Path
spec=importlib.util.spec_from_file_location('probe',Path(__file__).with_name('probe.py'));p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class Stream:
 def __init__(self,header):self.data=b'\x05\x00'+header+b'\x7f\x00\x00\x01\x00\x01'+b'T'*48
 def __enter__(self):return self
 def __exit__(self,*a):pass
 def settimeout(self,*a):pass
 def sendall(self,*a):pass
 def recv(self,n):d=self.data[:n];self.data=self.data[n:];return d
class Tests(unittest.TestCase):
 def runprobe(self,h):
  with patch.object(p.socket,'create_connection',return_value=Stream(h)),patch.object(p.secrets,'token_bytes',return_value=b'T'*48),patch.object(p.time,'sleep'):return p.probe(1,'tcp','127.0.0.1')
 def test_malformed_version(self):self.assertFalse(self.runprobe(b'\x04\x00\x00\x01')['probe_valid'])
 def test_malformed_reserved(self):self.assertFalse(self.runprobe(b'\x05\x00\x01\x01')['probe_valid'])
 def test_unknown_address(self):self.assertFalse(self.runprobe(b'\x05\x00\x00\x09')['probe_valid'])
 def test_valid_echo(self):self.assertTrue(self.runprobe(b'\x05\x00\x00\x01')['verified'])
 def test_valid_rejection(self):
  r=self.runprobe(b'\x05\x02\x00\x01');self.assertTrue(r['probe_valid']);self.assertFalse(r['verified']);self.assertEqual(r['outcome'],'socks_rejected')
if __name__=='__main__':unittest.main()
