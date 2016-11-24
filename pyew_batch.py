#!/usr/bin/python

import os
import sys
import time
import sqlite3

from hashlib import sha1

sys.path.append("pyew")
from pyew_core import CPyew

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
class CPyewAnalyser:
  def __init__(self):
    # Calculate prime numbers
    self.primes_table = primes(16384*4)
    self.db = open_db()
    self.db.printing = False
    
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

  def analyse(self, path):
    filename = path

    t = time.time()
    buf = open(filename, "rb").read()
    sha1_hash = sha1(buf).hexdigest()
    if self.file_exists(sha1_hash):
      log("Already existing file %s..." % sha1_hash)
      return ANALYSIS_ALREADY

    pyew = CPyew(batch=True)
    pyew.analysis_timeout = 300
    pyew.codeanalysis = True
    pyew.deepcodeanalysis = True

    try:
      pyew.loadFile(path)
      load_error = False
    except KeyboardInterrupt:
      log("Abort")
      return ANALYSIS_FAILED
    except:
      log("ERROR loading file %s" % path)
      load_error = True

    if not load_error:
      if pyew.format not in ["PE", "ELF", "bootsector"]:
        if pyew.format not in ["PDF", "OLE2"]:
          log("Not a known executable/document format")
        load_error = True

    if load_error:
      return ANALYSIS_FAILED

    primes = []
    total_functions = len(pyew.function_stats)
    if not load_error and total_functions > 0:
      nodes = []
      edges = []
      ccs = []
      callgraph = 1
      for x in pyew.function_stats:
        nodes.append(pyew.function_stats[x][0])
        edges.append(pyew.function_stats[x][1])
        cc = pyew.function_stats[x][2]
        ccs.append(cc)
        
        prime = self.primes_table[cc]
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
                   format=pyew.format, primes=primes, description=desc,\
                   analysis_date=time.asctime())
    return ANALYSIS_SUCCESS

#-----------------------------------------------------------------------
def usage():
  print "Usage:", sys.argv[0], "<executable file>"

#-----------------------------------------------------------------------
def main(path):
  anal = CPyewAnalyser()
  ret = anal.analyse(path)
  if ret > ANALYSIS_FAILED:
    sys.exit(0)
  sys.exit(1)

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main(sys.argv[1])
