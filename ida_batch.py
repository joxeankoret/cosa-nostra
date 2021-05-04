#!/usr/bin/python3

import os
import sys
import time
import sqlite3
import idautils
import ida_nalt
import ida_auto

from hashlib import sha1

from idc import *
from idaapi import *

from cn_log import log
from cn_db import init_web_db
from cosa_nostra import open_db

try:
  import pyclamd
except ImportError:
  log("No pyclamd support, files will not have a description.")
  pyclamd = None

#-----------------------------------------------------------------------
ANALYSIS_FAILED = 0
ANALYSIS_SUCCESS = 1
ANALYSIS_ALREADY = 2

#-----------------------------------------------------------------------
def ida_log(msg):
  log("COSA-NOSTRA: %s" % msg)

#-----------------------------------------------------------------------
def primes(n):
  if n==2: return [2]
  elif n<2: return []
  s=list(range(3,n+1,2))
  mroot = n ** 0.5
  half=(n+1)/2-1
  i=0
  m=3
  while m <= mroot:
    if s[i]:
      j=(m*m-3)/2
      j = int(j)
      s[j]=0
      while j<half:
        s[j]=0
        j+=m
    i=i+1
    m=2*i+3
  return [2]+[x for x in s if x]

#-----------------------------------------------------------------------
class CIDAAnalyser:
  def __init__(self):
    # Calculate prime numbers
    self.primes_table = primes(16384*4)
    self.db = open_db()
    self.db.printing = False
    
    self.callgraph = None
    self.primes = None
    
    self.clamd = None

  def get_description(self, buf):
    try:
      self.clamd = pyclamd.ClamdAgnostic()
      self.clamd.ping()

      ret = self.clamd.scan_stream(buf)
      if ret is None:
        return None

      # Answer format is in the following form:
      # >>> cd.scan_stream(buf)
      # >>> {u'stream': ('FOUND', 'Win.Trojan.Miniduke-3')}
      ret = ret["stream"][1]
      ida_log("Found malware name %s" % repr(ret))
      return ret
    except:
      ida_log("Clamd error: %s" % str(sys.exc_info()[1]))
      return None

  def file_exists(self, sha1_hash):
    what = "1"
    args = {"sha1":sha1_hash}
    where = "hash = $sha1"
    ret = self.db.select("samples", args, what=what, where=where)
    rows = list(ret)
    return len(rows) > 0

  def read_function(self, f):
    func = get_func(f)
    if func is None:
      return None

    q = idaapi.FlowChart(func)
    nodes = q.size
    edges = 0
    for node in q:
      edges += len(list(node.succs()))
    cc = edges - nodes + 2
    return nodes, edges, cc

  def try_search_functions(self):
    MakeUnknown(MinEA(), MaxEA() - MinEA(), DOUNK_EXPAND)
    for ea in idautils.Segments():
      segend = idc.GetSegmentAttr(ea, SEGATTR_END)
      start = ea
      while start < segend:
        if Byte(start) == 0xCC:
          start += 1
          continue

        MakeFunction(start)
        MakeCode(start)
        start = FindUnexplored(start+1, SEARCH_DOWN)

  def read_functions(self):
    ida_auto.auto_wait()

    primes = []
    l = list(Functions())
    total_functions = len(l)
    if total_functions == 0:
      self.try_search_functions()
      l = list(Functions())
      total_functions = len(l)
      if total_functions == 0:
        return ANALYSIS_FAILED

    nodes = []
    edges = []
    ccs = []
    callgraph = 1
    for f in l:
      f_nodes, f_edges, f_cc = self.read_function(f)
      nodes.append(f_nodes)
      edges.append(f_edges)
      cc = f_cc
      ccs.append(cc)

      prime = self.primes_table[cc]
      callgraph *= prime
      primes.append(prime)

    avg_nodes = abs(sum(nodes)/total_functions)
    avg_edges = abs(sum(edges)/total_functions)
    avg_ccs = abs(sum(ccs)/total_functions)
    
    self.callgraph = callgraph
    self.primes = primes

    return total_functions, avg_nodes, avg_edges, avg_ccs

  def analyse(self, path):
    filename = path

    t = time.time()
    buf = open(filename, "rb").read()
    sha1_hash = sha1(buf).hexdigest()
    if self.file_exists(sha1_hash):
      ida_log("Already existing file %s..." % sha1_hash)
      return ANALYSIS_ALREADY

    data = self.read_functions()
    if data is None or data == ANALYSIS_FAILED:
      return ANALYSIS_FAILED

    total_functions, avg_nodes, avg_edges, avg_ccs = data
    msg = "%d-%d-%d-%d" % (total_functions, avg_nodes, avg_edges, avg_ccs)
    ida_log("File analysed %s, callgraph signature %s" % (msg, self.callgraph))
    ida_log("Time to analyze %f" % (time.time() - t))

    abspath = os.path.abspath(filename)
    label = os.path.basename(os.path.dirname(abspath))

    callgraph = str(self.callgraph)
    primes = ",".join(map(str, self.primes))
    desc = self.get_description(buf)
    self.db.insert("samples", filename=filename, callgraph=callgraph,  \
                   hash=sha1_hash, total_functions=total_functions,    \
                   format=None, primes=primes, description=desc,\
                   analysis_date=time.asctime(),
                   label = label)
    return ANALYSIS_SUCCESS

#-----------------------------------------------------------------------
def usage():
  print("Usage:", sys.argv[0], "<executable file>")

#-----------------------------------------------------------------------
def main():
  anal = CIDAAnalyser()
  ret = anal.analyse(ida_nalt.get_input_file_path())
  if ret > ANALYSIS_FAILED:
    ida_log("Analysis successful")
    qexit(0)

  ida_log("Analysis failed")
  qexit(1)

if __name__ == "__main__":
  main()
