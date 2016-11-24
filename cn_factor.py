#!/usr/bin/python

import os
import gc
import sys
import string
import random
import decimal

from graphs import CGraph, CNode

#-----------------------------------------------------------------------
def primesbelow(N):
  # http://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n-in-python/3035188#3035188
  #""" Input N>=6, Returns a list of primes, 2 <= p < N """
  correction = N % 6 > 1
  N = {0:N, 1:N-1, 2:N+4, 3:N+3, 4:N+2, 5:N+1}[N%6]
  sieve = [True] * (N // 3)
  sieve[0] = False
  for i in range(long(N ** .5) // 3 + 1):
    if sieve[i]:
      k = (3 * i + 1) | 1
      sieve[k*k // 3::2*k] = [False] * ((N//6 - (k*k)//6 - 1)//k + 1)
      sieve[(k*k + 4*k - 2*k*(i%2)) // 3::2*k] = [False] * ((N // 6 - (k*k + 4*k - 2*k*(i%2))//6 - 1) // k + 1)
  return [2, 3] + [(3 * i + 1) | 1 for i in range(1, N//3 - correction) if sieve[i]]

#-----------------------------------------------------------------------
smallprimeset = set(primesbelow(100000))
_smallprimeset = 100000
def isprime(n, precision=7):
  # http://en.wikipedia.org/wiki/Miller-Rabin_primality_test#Algorithm_and_running_time
  if n == 1 or n % 2 == 0:
    return False
  elif n < 1:
    raise ValueError("Out of bounds, first argument must be > 0")
  elif n < _smallprimeset:
    return n in smallprimeset


  d = n - 1
  s = 0
  while d % 2 == 0:
    d //= 2
    s += 1

  for repeat in range(precision):
    a = random.randrange(2, n - 2)
    x = pow(a, d, n)

    if x == 1 or x == n - 1: continue

    for r in range(s - 1):
      x = pow(x, 2, n)
      if x == 1: return False
      if x == n - 1: break
    else: return False

  return True

#-----------------------------------------------------------------------
# https://comeoncodeon.wordpress.com/2010/09/18/pollard-rho-brent-integer-factorization/
def pollard_brent(n):
  if n % 2 == 0: return 2
  if n % 3 == 0: return 3

  y, c, m = random.randint(1, n-1), random.randint(1, n-1), random.randint(1, n-1)
  g, r, q = 1, 1, 1
  while g == 1:
    x = y
    for i in range(r):
      y = (pow(y, 2, n) + c) % n

    k = 0
    while k < r and g==1:
      ys = y
      for i in range(min(m, r-k)):
        y = (pow(y, 2, n) + c) % n
        q = q * abs(x-y) % n
      g = gcd(q, n)
      k += m
    r *= 2
  if g == n:
    while True:
      ys = (pow(ys, 2, n) + c) % n
      g = gcd(abs(x - ys), n)
      if g > 1:
        break

  return g

#-----------------------------------------------------------------------
# might seem low, but 1000*1000 = 1000000, so this will fully factor
# every composite < 1000000
smallprimes = primesbelow(1000)
def primefactors(n, sort=False):
  factors = []

  limit = long(n ** decimal.Decimal(.5)) + 1
  for checker in smallprimes:
    if checker > limit: break
    while n % checker == 0:
      factors.append(checker)
      n //= checker
      limit = long(n ** decimal.Decimal(.5)) + 1
      if checker > limit: break

  if n < 2: return factors

  while n > 1:
    if isprime(n):
      factors.append(n)
      break
    factor = pollard_brent(n) # trial division did not fully factor, switch to pollard-brent
    factors.extend(primefactors(factor)) # recurse to factor the not necessarily prime factor returned by pollard-brent
    n //= factor

  if sort: factors.sort()

  return factors

#-----------------------------------------------------------------------
def factorization(n):
  factors = {}
  for p1 in primefactors(n):
    try:
      factors[p1] += 1
    except KeyError:
      factors[p1] = 1
  return factors

#-----------------------------------------------------------------------
totients = {}
def totient(n):
  if n == 0: return 1

  try: return totients[n]
  except KeyError: pass

  tot = 1
  for p, exp in factorization(n).items():
    tot *= (p - 1)  *  p ** (exp - 1)

  totients[n] = tot
  return tot

#-----------------------------------------------------------------------
def gcd(a, b):
  if a == b: return a
  while b > 0: a, b = b, a % b
  return a

#-----------------------------------------------------------------------
def lcm(a, b):
  return abs(a * b) // gcd(a, b)

#-----------------------------------------------------------------------
FACTORS_CACHE = {}
def difference(num1, num2):
  """ Calculate the difference in prime numbers. If a primer number does not 
      exists in one group but does in the other, the total value of the prime
      number is added as differences. If a primer number exists in both groups
      the values difference is added. """
  nums = [num1,
          num2]
  s = []
  for num in nums:
    if FACTORS_CACHE.has_key(num):
      x = FACTORS_CACHE[num]
    else:
      x = factorization(long(num))
      FACTORS_CACHE[num] = x
    s.append(x)

  diffs = {}
  for x in s[0].keys(): # XXX: FIXME: Do not calculate again and again!
    if x in s[1].keys(): # XXX: FIXME: Do not calculate again and again!
      if s[0][x] != s[1][x]:
        diffs[x] = max(s[0][x], s[1][x]) - min(s[0][x], s[1][x])
    else:
      diffs[x] = s[0][x]
  
  for x in s[1].keys(): # XXX: FIXME: Do not calculate again and again!
    if x in s[0].keys(): # XXX: FIXME: Do not calculate again and again!
      if s[1][x] != s[0][x]:
        diffs[x] = max(s[0][x], s[1][x]) - min(s[0][x], s[1][x])
    else:
      diffs[x] = s[1][x]

  ret = sum(diffs.values())
  return ret

#-----------------------------------------------------------------------
def difference_matrix(samples, debug=True):
  """ Calculate the difference matrix for the given set of samples. """

  DIFF_CACHE = {}
  # XXX: FIXME: Could this be 'pushed' totally to SQLite by registering "difference" as a function?
  diff_matrix = {}
  matches = 0
  no_matches = 0
  total_iterations = len(samples) * len(samples)
  iteration = 0
  it2 = 0
  for x in samples:
    if debug:
      print "Calculating difference matrix for %s, iteration %d out of %d (%d matches, %d cache misses)" % (x, iteration, total_iterations, matches, no_matches)

    if it2 % 1000 == 0:
      # Horrible. For one of the "optimizations" for this algorithm it 
      # tries to remember the difference matrix for already clustered
      # samples. However, depending on the number of samples, it might
      # cause a too big RAM consumption. Thus, we need to flush memory
      # from time to time. In an AMD64 + 32GB RAM machine, it seems that
      # RAM goes beyond 3GB after the number of elements in the dict is
      # beyond 1,000,000 elements so, as an aweful workaround, flush it
      # when it has more than that number of elements. Ideas to fix this
      # are welcome...
      if len(DIFF_CACHE) > 1000000:
        if debug:
          print "Too much memory being used, freeing up..."

        DIFF_CACHE = {}
        gc.collect()
    it2 += 1

    if not x in diff_matrix:
      diff_matrix[x] = {}
    for y in samples:
      iteration += 1
      if samples[x] != samples[y]:
        # If we already clustered 2 malware samples for which the whole
        # list of primes is already clustered, do not try to cluster
        # them again, just use the previously calculated diff matrix.
        key = str(long(samples[x]) * long(samples[y]))
        if key in DIFF_CACHE:
          d = DIFF_CACHE[key]
          matches += 1
        else:
          no_matches += 1
          d = difference(samples[x], samples[y])
          DIFF_CACHE[key] = d

        diff_matrix[x][y] = d
      else:
        diff_matrix[x][y] = 0

  return diff_matrix

#-----------------------------------------------------------------------
class CFuzzyGraphMatcher(object):
  """ Fuzzy graph matcher. Create groups and phylogenetic trees based on input
      data calculated from the call graph and flow graph of a program using
      Pyew (or IDA). """
  def __init__(self, samples, max_diff=20, diff_relative=True, debug=True):
    self.samples = samples
    self.diff_matrix = {}
    self.diff_relative = diff_relative
    self.max_diff = 20
    self.debug = debug
    self.groups = []
    self.trees = []
    self.last_letter = 0
    self.ascii_letters = self.generate_ascii_letters()

    if self.debug:
      print "Total of %d sample(s) in set" % len(samples)

    self.groups_done = set()

    # Used exclusively as an optimization for the algorithm
    self.clustered_samples = set()

  @staticmethod
  def load_from_file(filename, max_diff=20, diff_relative=True, debug=True):
    """ Return a CFuzzyGraphMatcher object with all the samples data loaded
        from @filename. """
    f = open(filename, "rb")
    samples = {}
    for line in f.readlines():
      line = line.strip("\r").strip("\n")
      data = line.split(";")
      samples[data[0]] = data[5]
    f.close()

    return CFuzzyGraphMatcher(samples, max_diff, diff_relative, debug)

  def generate_ascii_letters(self):
    ret = []
    for i in range(10):
      for x in string.ascii_lowercase:
        for y in string.ascii_lowercase:
          ret.append(x+y+str(i))
    return ret

  def create_group_for(self, sample1):
    """ Create a group for the given sample after calculating the distance
        matrix. """

    # Do not cluster again samples already clustered
    if sample1 in self.clustered_samples and False:
      return
    self.clustered_samples.add(sample1)

    # FIXME: The number of functions is in the input data, there is no need
    # to recalculate it again!
    total_functions = sum(FACTORS_CACHE[self.samples[sample1]].values())
    for sample2 in self.diff_matrix[sample1]:
      value = self.diff_matrix[sample1][sample2]
      match = False
      if self.diff_relative: # when relative, we consider max_diff a percent
        if value*100/total_functions <= self.max_diff:
          if self.debug and False:
            print "\t %s - %d (%s%f percent)" % (sample2, value, "%", value*100./total_functions)
          match = True
      else: # otherwise, it's a fixed value
        if value <= self.max_diff:
          if self.debug and False:
            print "\t %s - %d" % (sample2, value)
          match = True
      
      # We have a match, add the samples to 1 group, finding first if any of
      # the samples is already in a group.
      if match:
        added = False
        for group in self.groups:
          if sample1 in group:
            group.add(sample2)
            self.clustered_samples.add(sample2)
            added = True
            # the sample can be in various groups!
            #break
          elif sample2 in group:
            group.add(sample1)
            self.clustered_samples.add(sample2)
            added = True
            # the sample can be in various groups!
            #break

        if not added:
          self.groups.append(set([sample1, sample2]))

  def merge_groups(self):
    """ Merge groups sharing some elements into just one group. """
    for group1 in self.groups:
      for group2 in self.groups:
        if group1 == group2:
          continue
        if len(group1.intersection(group2)) > 0:
          group1.update(group2)
          group2 = set()

  def cluster(self):
    """ Group the samples according to the their difference matrix. Neighbor
        joining method. """
    # Calculate the difference matrix of all samples and check all of them
    self.diff_matrix = difference_matrix(self.samples, self.debug)
    for sample1 in self.diff_matrix:
      self.create_group_for(sample1)

    self.merge_groups()

  def get_diff_matrix_for(self, group, diff_matrix=None):
    """ Get a difference matrix for the given group. """    
    if diff_matrix is None:
      diff_matrix = self.diff_matrix

    dm = {}
    for s1 in group:
      if not dm.has_key(s1):
        dm[s1] = {}
      for s2 in group:
        if s1 == s2:
          dm[s1][s2] = 0
        else:
          dm[s1][s2] = diff_matrix[s1][s2]

    return dm

  def get_q_matrix(self, D):
    """
    @param D: a row major distance matrix
    @return: a row major matrix whose minimum off-diagonal defines the neighbor indices to be joined
    """
    lowest = None
    n = len(D)
    D_star = [sum(D[i].values()) for i in D.keys()]
    Q = []
    i = 0
    for s1 in D.keys():
      row = []
      j = 0
      for s2 in D.keys():
        if s1 == s2:
          element = 0
        else:
          element = (n - 2) * D[s1][s2] - D_star[i] - D_star[j]
        if lowest is None or element < lowest:
          lowest = element
        row.append(element)
        j += 1
      i += 1
      Q.append(row)

    return Q, lowest

  def get_dfg_distances(self, n1, n2, dm):
    # Calculate the start and the total number of elements
    n = len(dm)
    D_star = [sum(dm[i].values()) for i in dm.keys()]
    
    f = g = -1
    i = 0
    for x in dm.keys():
      if x == n1 and f == -1:
        f = i
      elif x == n2 and g == -1:
        g = i
      if f != -1 and g != -1:
        break
      i += 1

    # calculate the difference from n1 to the new node
    dfu = (dm[n1][n2]) / 2. + (1. / 2*(n-2)) * (D_star[f] - D_star[g])
    # calculate the difference from n2 to the new node
    dgu = (dm[n1][n2]) / 2. + (1. / 2*(n-2)) * (D_star[f] - D_star[g])
    return dfu, dgu

  def update_diff_matrix(self, node, n1, n2, group, diff_matrix):
    diff_matrix[node] = {node:0}
    for s1 in group:
      if s1 == node:
        continue
      diff_matrix[s1][node] = (diff_matrix[n1][s1] + diff_matrix[n2][n1] - diff_matrix[n1][n2]) / 2.
      diff_matrix[node][s1] = diff_matrix[s1][node]
    return diff_matrix

  def make_tree_for(self, group):
    """ Make a phylogenetic tree for the given group. """
    
    l = list(group)
    l.sort()
    s = str(l)
    if s in self.groups_done:
      if self.debug:
        print "Already clustered group found, skipping..."
      return None

    g = CGraph()
    g.letter = self.ascii_letters[self.last_letter]
    self.last_letter += 1

    group = list(group)
    dm = self.diff_matrix
    parent = None
    name = "New node %d"
    node_num = 0
    nodes = {}
    previous_node_name = node_name = None

    total_groups = len(group)-1
    groups = 0
    for it in xrange(len(group)-1):
      groups += 1
      node_num += 1
      # start by building a smaller difference matrix only for the samples
      # in this specific group
      dm = self.get_diff_matrix_for(group, dm)
      qm, lowest = self.get_q_matrix(dm)
      group = dm.keys()

      new_group = list(group)
      # Build a new node with the highest value found so far
      if node_name is not None:
        previous_node_name = node_name
      node_name = name % node_num
      n = CNode(node_name, shape="point")
      g.addNode(n)
      nodes[node_name] = n

      if parent is None:
        parent = n

      # Create the edges between the new node 'n' and the samples wih the
      # lowest Q matrix value
      if it != 0:
        lowest = None

      n1, n2 = self.get_neighbors(qm, group, lowest, previous_node_name)
      if not nodes.has_key(n1):
        nodes[n1] = CNode(n1)
      if not nodes.has_key(n2):
        nodes[n2] = CNode(n2)

      dfu = dgu = 0 #self.get_dfg_distances(n1, n2, dm)
      if not g.edgeExists(nodes[n1], n):
        g.addEdge(n, nodes[n1], check_dups=True, label=str(dfu))
      if not g.edgeExists(nodes[n2], n):
        g.addEdge(n, nodes[n2], check_dups=True, label=str(dgu))
      if n1 in new_group:
        new_group.remove(n1)
      if n2 in new_group:
        new_group.remove(n2)
      new_group.append(node_name)

      dm = self.update_diff_matrix(node_name, n1, n2, new_group, dm)
      group = new_group

    self.groups_done.add(s)
    return g

  def get_neighbors(self, qm, group, lowest, node=None):
    if node is not None:
      idx = group.index(node)
      #pprint.pprint(qm)
      value = min(qm[idx])
      lowest = value
      
      n = len(qm)
      q = [(qm[i][j], (i, j)) for i in range(n) for j in range(n) if i<j]
      value, pair = min(q)
      n1 = group[pair[0]]
      n2 = group[pair[1]]
    else:
      i = 0
      done = False
      n1 = n2 = None
      for row in qm:
        j = 0
        if done:
          break
        for col in row:
          if qm[i][j] == lowest:
            if n1 is None:
              n1 = group[i]
            if n2 is None:
              n2 = group[j]
            
            if node is not None:
              if n1 == node:
                n1 = None
                continue
              elif n2 == node:
                n2 = None
                continue
              elif n1 == n2:
                n2 = None
                continue
  
            done = True
            #new_node = self.get_new_node(n1, n2, dm)
            break
          j += 1
        i += 1
    return n1, n2

  def make_tree(self, to_dot=True):
    """ Create a phylogenetic tree for every cluster. """
    if len(self.groups) == 0 and len(self.diff_matrix) == 0:
      self.cluster()

    if to_dot:
      ret = ["digraph G {"]

    final_groups = []
    l = list(self.groups)
    total_groups = len(l)
    i = 0
    for group in l:
      if len(group) < 3:
        continue

      if self.debug:
        line = "Making tree for group with %d sample(s), iteration %d out of %d"
        print line % (len(group), i, total_groups)
      
      i += 1

      tmp = self.make_tree_for(group)
      if tmp is not None:
        final_groups.append(tmp)
        if to_dot:
          ret.append(tmp.toDot().replace("digraph", "subgraph"))

    if to_dot:
      ret.append("}")
      return "\n".join(ret)

    return final_groups

  def cluster_to_data(self):
    self.cluster()
    for group in self.groups:
      for sample in group:
        print "%s;;;;;%s" % (sample, self.samples[sample])
      print

#-----------------------------------------------------------------------
def main(path):
  fgm = CFuzzyGraphMatcher.load_from_file(path, 50, True, debug=False)
  print fgm.make_tree(to_dot=True)

#-----------------------------------------------------------------------
def usage():
  print "Usage:", sys.argv[0], "<CSV file>"

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main(sys.argv[1])
