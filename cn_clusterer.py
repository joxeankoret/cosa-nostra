#!/usr/bin/python

import os
import re
import sys
import time
import json

from cn_log import log
from cosa_nostra import open_db
from cn_factor import CFuzzyGraphMatcher, FACTORS_CACHE

#-----------------------------------------------------------------------
class CSamplesClusterer:
  def __init__(self):
    self.wait_time = 60
    self.db = open_db()
    self.db.printing = False

  def build_cluster_name(self, samples, d):
    name = set()
    for sample in samples:
      if sample in d:
        name.add(d[sample])
    
    if len(name) == 0:
      return None
    return "\n".join(name)

  def get_cluster_hashes(self, samples, d):
    hashes = set()
    for sample in samples:
      if sample in d:
        hashes.add(d[sample][1])
    return hashes

  def get_cluster_functions_range(self, samples, d):
    min_funcs = -1
    max_funcs = -1
    for sample in samples:
      if sample in d:
        total_functions = d[sample][0]
        if total_functions > max_funcs:
          max_funcs = total_functions
        elif total_functions < min_funcs or min_funcs == -1:
          min_funcs = total_functions

    return min_funcs, max_funcs

  def build_cluster_tags(self, cluster_name):
    if cluster_name is None:
      return None

    ret = set()
    l = re.split("\W+", cluster_name)
    for x in l:
      if x.isdigit():
        continue
      ret.add(x)
    return json.dumps(list(ret))

  def create_or_update_clusters(self, g, raw_samples):
    # Build a dict with id -> description
    d_samples = {}
    d_functions = {}
    min_funcs = -1
    max_funcs = -1
    for sample in raw_samples:
      d_functions[sample["id"]] = [int(sample["total_functions"]), sample["hash"]]
      if sample["description"] is not None:
        d_samples[sample["id"]] = sample["description"]

    for cluster in g:
      # Only process clusters with more than 1 item
      if len(cluster) <= 1:
        continue

      generation_level = 0

      # Get the cluster's samples and the graph (a dictionary)
      new_d = {}
      cluster_samples = set()
      d = cluster.d
      for key in d:
        if key.name.isdigit():
          cluster_samples.add(int(key))
        else:
          generation_level += 1

        new_d[str(key)] = map(str, d[key])

        for x in d[key]:
          if x.name.isdigit():
            cluster_samples.add(int(x.name))

      # Get the final field's values that will be inserted in the
      # clusters table
      cluster_name = self.build_cluster_name(cluster_samples, d_samples)
      cluster_tags = self.build_cluster_tags(cluster_name)
      cluster_graph = json.dumps(new_d)
      cluster_hashes = self.get_cluster_hashes(cluster_samples, d_functions)
      cluster_hashes = json.dumps(list(cluster_hashes))
      cluster_samples_j = json.dumps(list(cluster_samples))
      l = self.get_cluster_functions_range(cluster_samples, d_functions)
      min_funcs, max_funcs = l
      dot = cluster.toDot()

      if cluster_name:
        log("Creating cluster with name %s..." % repr(cluster_name))
      else:
        log("Creating unnamed cluster...")

      with self.db.transaction():
        self.db.insert("clusters", description=cluster_name,           \
                graph=cluster_graph, generation_level=generation_level,\
                samples=cluster_samples_j, last_update=time.asctime(), \
                max_funcs=max_funcs, min_funcs=min_funcs, dot=dot,     \
                tags=cluster_tags)

        c_vars = {"samples":list(cluster_samples)}
        where = "id in $samples"
        self.db.update("samples", vars=c_vars, where=where, clustered=1)

    return True

  def to_primes_dict(self, primes):
    d = {}
    for prime in primes:
      try:
        prime = long(prime)
        d[prime] += 1
      except:
        d[prime] = 1
    return d

  def cluster_samples(self, raw_samples):
    samples = {}
    for sample in raw_samples:
      samples[str(sample["id"])] = sample["callgraph"]
      callgraph = sample["callgraph"]
      primes = sample["primes"].split(",")
      FACTORS_CACHE[callgraph] = self.to_primes_dict(primes)

    fgm = CFuzzyGraphMatcher(samples, max_diff=20, diff_relative=True, debug=True)
    log("Creating phylogenetic trees...")
    g = fgm.make_tree(to_dot=False)

    log("Creating or updating clusters...")
    ret = self.create_or_update_clusters(g, raw_samples)

    log("Done processing phylogenetic trees!")
    return ret

  def find_new_samples(self):
    what = "id, hash, description, callgraph, total_functions, primes"
    where = "clustered != 1 and total_functions >= 100"
    order = "id asc"
    ret = self.db.select("samples", what=what, where=where, order=order)
    rows = list(ret)
    if len(rows) == 0:
      return False
    log("Found a total %d new sample(s) to cluster" % len(rows))
    return self.cluster_samples(rows)

  def find_clusters(self):
    log("Finding new samples to cluster...")
    while 1:
      ret = self.find_new_samples()
      break
      if ret:
        log("Waiting for %d second(s)..." % self.wait_time)
      time.sleep(self.wait_time)
      break
    log("Done")

#-----------------------------------------------------------------------
def main():
  clusterer = CSamplesClusterer()
  clusterer.find_clusters()

if __name__ == "__main__":
  if os.getenv("PROFILE_CLUSTERER") is not None:
    import cProfile
    profiler = cProfile.Profile()
    profiler.runcall(main)
    profiler.print_stats(sort="time")
  else:
    main()
