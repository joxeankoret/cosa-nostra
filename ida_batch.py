#!/usr/bin/python

import os
import sys
import time
import sqlite3

from hashlib import sha1

from idc import *
from idaapi import *

from cn_log import log
from cn_db import init_web_db
from cosa_nostra import open_db

#-----------------------------------------------------------------------
ANALYSIS_FAILED = 0
ANALYSIS_SUCCESS = 1
ANALYSIS_ALREADY = 2

#-----------------------------------------------------------------------
def primes(n):
  if n==2: return [2]
  elif n<2: return []
  s=range(3,n+1,2)
  mroot = n ** 0.5
  half=(n+1)/2-1
  i=0
  m=3
  while m <= mroot:
    if s[i]:
      j=(m*m-3)/2
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

  def read_functions(self):
    autoWait()

    primes = []
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

    return total_functions, avg_nodes, avg_edges, avg_ccs

  def analyse(self, path):
    filename = path

    t = time.time()
    buf = open(filename, "rb").read()
    sha1_hash = sha1(buf).hexdigest()
    if self.file_exists(sha1_hash):
      log("Already existing file %s..." % sha1_hash)
      return ANALYSIS_ALREADY

    data = self.read_functions()
    if data is None:
      return ANALYSIS_FAILED

    total_functions, avg_nodes, avg_edges, avg_ccs = data
    msg = "%d-%d-%d-%d" % (total_functions, avg_nodes, avg_edges, avg_ccs)
    log("File analysed %s, callgraph signature %s" % (msg, callgraph))
    log("Time to analyze %f" % (time.time() - t))

    callgraph = str(callgraph)
    primes = ",".join(map(str, primes))
    desc = None # We don't have pyclamd in IDA...
    self.db.insert("samples", filename=filename, callgraph=callgraph,  \
                   hash=sha1_hash, total_functions=total_functions,    \
                   format=None, primes=primes, description=desc,\
                   analysis_date=time.asctime())
    return ANALYSIS_SUCCESS

#-----------------------------------------------------------------------
def usage():
  print "Usage:", sys.argv[0], "<executable file>"

#-----------------------------------------------------------------------
def main():
  anal = CIDAAnalyser()
  ret = anal.analyse(GetInputFilePath())
  if ret > ANALYSIS_FAILED:
    qexit(0)
  qexit(1)

if __name__ == "__main__":
  main()
