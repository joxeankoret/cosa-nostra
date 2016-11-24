#!/usr/bin/python

import os
import sys
import time
import thread
import sqlite3
import threading

import r2pipe

from hashlib import sha1

try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO

try:
  import pyclamd
except ImportError:
  log("No pyclamd support, files will not have a description.")
  pyclamd = None

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
def self_kill():
  log("*** TIMEOUT *** KILLING MY SELF!")
  thread.interrupt_main()

#-----------------------------------------------------------------------
class CR2Analyser:
  def __init__(self):
    # Calculate prime numbers
    self.primes_table = primes(16384*4)
    self.db = open_db()
    self.db.printing = False
    
    self.r2 = None
    self.clamd = None
    if pyclamd is not None:
      self.clamd = pyclamd.ClamdAgnostic()
      self.clamd.ping()

  def file_exists(self, sha1_hash):
    what = "1"
    args = {"sha1":sha1_hash}
    where = "hash = $sha1"
    ret = self.db.select("samples", args, what=what, where=where)
    rows = list(ret)
    return len(rows) > 0

  def get_description(self, buf):
    if self.clamd is None:
      return None

    ret = self.clamd.scan_stream(buf)
    if ret is None:
      return None

    # Answer format is in the following form:
    # >>> cd.scan_stream(buf)
    # >>> {u'stream': ('FOUND', 'Win.Trojan.Miniduke-3')}
    ret = ret["stream"][1]
    log("Found malware name %s" % repr(ret))
    return ret

  def get_edges(self, lines):
    l = set()
    for line in lines:
      line = line.strip("\n")
      fields = line.split(" ")
      if len(fields) > 1:
        f1, f2 = fields[0], fields[1]
        l.add((f1, f2))
        
        if len(fields) > 4:
          print "fields", fields
          is_jump = False
          for field in fields[4:]:
            if not is_jump:
              is_jump = field == "j"
            elif is_jump:
              l.add((f1, field))
              is_jump = False
    
    print l
    print len(l)
    raw_input("?")

  def read_function(self, f):
    offset = f["offset"]
    l = self.r2.cmdj("afij @0x%x" % offset)
    if len(l) > 0:
      d = l[0]
      edges = d["edges"]
      nodes = d["nbbs"]
      cc = nodes - edges + 2
      return nodes, edges, cc

    return None

  def analyse(self, path):
    filename = path

    t = time.time()
    buf = open(filename, "rb").read()
    sha1_hash = sha1(buf).hexdigest()
    if self.file_exists(sha1_hash):
      log("Already existing file %s..." % sha1_hash)
      return ANALYSIS_ALREADY

    try:
      self.r2 = r2pipe.open(path)
      load_error = False
    except KeyboardInterrupt:
      log("Abort")
      return ANALYSIS_FAILED
    except:
      log("ERROR loading file %s" % path)
      load_error = True

    # Before performing code analysis, install a thread to immolate us
    # if it takes too long...
    kill_thread = threading.Timer(60, self_kill)
    kill_thread.start()
    try:
      self.r2.cmd("aaa")
      # Cancel it as soon as the analysis finishes
      kill_thread.cancel()
    except:
      load_error = True

    if load_error:
      return ANALYSIS_FAILED

    fmt = None
    r2_format = self.r2.cmdj("ij")
    if r2_format is not None and "bin" in r2_format:
      fmt = r2_format["bin"]["class"]

    primes = []
    functions = self.r2.cmdj("aflj")
    if functions is None:
      return ANALYSIS_FAILED

    total_functions = len(functions)
    if not load_error and total_functions > 0:
      nodes = []
      edges = []
      ccs = []
      callgraph = 1
      for f in functions:
        ret = self.read_function(f)
        if ret is None:
          # Sometimes, it might fail in radare2 for some functions
          continue

        f_nodes, f_edges, f_cc = ret
        nodes.append(f_nodes)
        edges.append(f_edges)
        ccs.append(f_cc)
        
        prime = self.primes_table[f_cc]
        callgraph *= prime
        primes.append(prime)

      avg_nodes = abs(sum(nodes)/total_functions)
      avg_edges = abs(sum(edges)/total_functions)
      avg_ccs = abs(sum(ccs)/total_functions)
    elif load_error:
      total_functions = avg_nodes = avg_edges = avg_ccs = -1
      callgraph = -1

    msg = "%d-%d-%d-%d" % (total_functions, avg_nodes, avg_edges, avg_ccs)
    log("File analysed %s, callgraph signature %s" % (msg, callgraph))
    log("Time to analyze %f" % (time.time() - t))

    callgraph = str(callgraph)
    primes = ",".join(map(str, primes))
    desc = self.get_description(buf)
    self.db.insert("samples", filename=filename, callgraph=callgraph,  \
                   hash=sha1_hash, total_functions=total_functions,    \
                   format=fmt, primes=primes, description=desc,\
                   analysis_date=time.asctime())
    return ANALYSIS_SUCCESS

#-----------------------------------------------------------------------
def usage():
  print "Usage:", sys.argv[0], "<executable file>"

#-----------------------------------------------------------------------
def main(path):
  anal = CR2Analyser()
  ret = anal.analyse(path)
  if ret > ANALYSIS_FAILED:
    sys.exit(0)
  sys.exit(1)

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main(sys.argv[1])
