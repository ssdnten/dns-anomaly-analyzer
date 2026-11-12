import unittest
from main import analyze

def row(query='demo.example',rcode='NXDOMAIN'): return dict(client='192.0.2.1',query=query,rcode=rcode)
class Tests(unittest.TestCase):
    def test_ratio(self): self.assertIn('high_nxdomain_ratio',analyze([row()]*3+[row(rcode='NOERROR')]*2)[0]['reasons'])
    def test_minimum(self): self.assertEqual(analyze([row()])[0]['reasons'],[])
    def test_long_label(self): self.assertIn('long_first_label',analyze([row('a'*40+'.example')])[0]['reasons'])
    def test_unique(self): self.assertEqual(analyze([row('DEMO.EXAMPLE.'),row()])[0]['unique_queries'],1)
    def test_empty(self): self.assertEqual(analyze([]),[])
    def test_invalid_query(self):
        with self.assertRaises(ValueError): analyze([row('a'*64+'.example')])
    def test_invalid_threshold(self):
        with self.assertRaises(ValueError): analyze([],min_queries=0)
