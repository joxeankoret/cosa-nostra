#!/usr/bin/env python

import random

#-----------------------------------------------------------------------
class CGmlGraph:
  def __init__(self, g):
    self.g = g

  def generate(self):
    buf = "graph [ \n"
    nodes = self.g.nodes()
    
    for node in nodes:
      name = node.name
      num = nodes.index(node)
      
      buf += 'node [ id %s \n label "%s"\n fill "blue" \n type "oval"\n LabelGraphics [ type "text" ] ] \n' % (num, name)
    buf += "\n"
    
    i = 0
    for parent in self.g.d:
      p = nodes.index(parent)
      for child in self.g.d[parent]:
        c = nodes.index(child)
        buf += " edge [ source %s \n target %s ]\n" % (p, c)
    
    buf += "]"
    return buf

#-----------------------------------------------------------------------
class CDotGraph:
  def __init__(self, g):
    self.g = g
    self.letter = "a"

  def generate(self):
    buf = 'digraph G {\n graph [overlap=scale]; node [fontname=Courier]; \n\n'
    nodes = self.g.nodes()
    
    for node in nodes:
      name = node.name.replace('"', r'\"')
      num = nodes.index(node)
      
      buf += ' %s%s [shape=%s, label = "%s", color="blue"]\n' % (self.letter, num, node.shape, name)
    buf += "\n"

    for parent in self.g.d:
      p = nodes.index(parent)
      for child in self.g.d[parent]:
        c = nodes.index(child)
        val = self.g.weights[parent,child]
        if val is None:
          color = "red"
        elif val == 0:
          color = "blue"
        elif val == 1:
          color = "green"
        else:
          color = "red"
        
        label = self.g.weights[parent,child]
        if label is not None:
          label = ", label=%s" % label
        else:
          label = ""
        buf += " %s%s -> %s%s [style = bold, color=%s%s]\n" % (self.letter, p, self.letter, c, color, label)
    
    buf += "}"
    return buf

#-----------------------------------------------------------------------
class CNode(object):
  def __init__(self, name, data=None, label=None, shape="box"):
    self.name = name
    self.data = data
    self.label = label
    self.shape = shape

  def __str__(self):
    return self.name

  def __repr__(self):
    return self.__str__()

#-----------------------------------------------------------------------
class CGraph(object):
  def __init__(self):
    self.d = {}
    self.weights = {}
    self.labels = {}
    self.letter = "a"

  def __str__(self):
    return str(self.d)

  def __repr__(self):
    return self.__str__()

  def __len__(self):
    return len(self.d)

  def clear(self):
    self.d.clear()

  def setDict(self, d):
    self.d = d

  def has_key(self, x):
    return self.d.has_key(x)

  def hash(self):
    ret = []
    keys = self.d.keys()
    keys.sort()
    for key in keys:
      values = map(str, self.d[key])
      values.sort()
      copy_values = []
      for value in values:
        copy_values.append("'%s'" % str(value))
      v = "'%s':[%s]" % (key, ", ".join(copy_values))
      ret.append(v)
    return "{" + ",".join(ret) + "}"
  
  def checkHash(self, d):
    #if type(d) is not dict:
    #  raise Exception("Invalid hash")
    
    d2 = eval(self.hash())
    return d == d2

  def addNode(self, node):
    self.d[node] = []
  
  def delNode(self, n):
    if self.d.has_key(n):
      del self.d[n]
    
    for n2 in list(self.d):
      if n in self.d[n2]:
        self.d[n2].remove(n)

  def addVertex(self, edge):
    self.addNode(edge)

  def addEdge(self, n1, n2, check_dups=False, value=None, label=None):
    if not self.d.has_key(n1):
      self.d[n1] = []
    
    if check_dups:
      if n2 in self.d[n1]:
        return
    
    self.d[n1].append(n2)
    self.weights[(n1, n2)] = value
    self.labels[(n1,n2)] = label
  
  def edgeExists(self, n1, n2):
    if not self.d.has_key(n1):
      return False
    return n2 in self.d[n1]

  def getWeight(self, n1, n2):
    if self.weights.has_key((n1, n2)):
      return self.weights[(n1, n2)]
    else:
      return None

  def hasChildren(self, n):
    return len(self.d[n]) > 0

  def hasParents(self, n):
    for n2 in self.d:
      if n in self.d[n2]:
        return True
    return False

  def node(self, name):
    for n in self.d:
      if n.name == name:
        return n
    
    return None

  def searchPath(self, start, end, path=[]):
    path = path + [start]
    if start == end:
      return path
    
    if not self.d.has_key(start):
      return None
    
    for node in self.d[start]:
      if node not in path:
        newpath = self.searchPath(node, end, path)
        if newpath:
          return newpath
    
    return None

  def searchAllPaths(self, start, end, path=[]):
    path = path + [start]
    
    if start == end:
      yield path
    elif not self.d.has_key(start):
      yield None
    else:
      for node in self.d[start]:
        if node not in path:
          newpaths = self.searchAllPaths(node, end, path)
          for newpath in newpaths:
            yield newpath

  def searchLongestPath(self, astart, aend):
    longest = None
    l = self.searchAllPaths(astart, aend)
    
    for path in l:
      if path is None:
        continue
      
      if longest is None or len(path) > len(longest):
        longest = path
    
    return longest

  def searchShortestPath(self, start, end, path=[]):
    path = path + [start]
    if start == end:
      return path
    if not self.d.has_key(start):
      return None
    
    shortest = None
    for node in self.d[start]:
      if node not in path:
        newpath = self.searchPath(node, end, path)
        if newpath:
          if not shortest or len(shortest) > len(newpath):
            shortest = newpath
    
    return shortest

  def addGraph(self, g2):
    for key in list(g2.d):
      if not self.d.has_key(key):
        self.d[key] = []
      
      for value in list(g2.d[key]):
        self.d[key].append(value)

  def nodes(self):
    l = []
    for father in self.d:
      if father not in l:
        l.append(father)
      
      for child in self.d[father]:
        if child not in l:
          l.append(child)
    return l

  def toAdjacencyList(self):
    l = ()
    for father in self.d:
      for child in self.d[father]:
        l += ((father, child), )
    
    return l

  def fromAdjacencyList(self, l):
    for element in l:
      k, v = element
      if not self.d.has_key(k):
        self.d[k] = []
      
      if v not in self.d[k]:
        self.d[k].append(v)

  def fromDict(self, d):
    l = set()
    l.update(d.keys())
    for x in d.values():
      l.update(x)

    nodes = {}
    for node in l:
      nodes[node] = CNode(node)
      self.addNode(nodes[node])

    for key in d:
      for element in d[key]:
        self.addEdge(nodes[key], nodes[element])

  def toAdjacencyMatrix(self):
    nodes = self.nodes()
    nodes.sort()
    
    x = []
    for n1 in nodes:
      y = []
      for n2 in nodes:
        if not self.d.has_key(n2) or n1 not in self.d[n2]:
          v = 0
        else:
          v = 1
        y.append(v)
      
      x.append(y)
    
    return nodes, x

  def toGml(self):
    gml = CGmlGraph(self)
    return gml.generate()
  
  def toDot(self):
    dot = CDotGraph(self)
    dot.letter = self.letter
    return dot.generate()

  def isSubgraph(self, g2):
    for node in g2.d:
      if node not in self.d:
        return False
      
      for subnode in g2.d[node]:
        if subnode not in self.d[node]:
          return False
    
    return True

  def intersect(self, g):
    l1 = set(self.toAdjacencyList())
    l2 = set(g.toAdjacencyList())    
    r = l1.intersection(l2)
    
    return r

  def union(self, g):
    l1 = set(self.toAdjacencyList())
    l2 = set(g.toAdjacencyList())    
    r = l1.union(l2)
    
    return r

  def difference(self, g):
    l1 = set(self.toAdjacencyList())
    l2 = set(g.toAdjacencyList())    
    r = l1.difference(l2)
    
    return r
  
  def symmetricDifference(self, g):
    l1 = set(self.toAdjacencyList())
    l2 = set(g.toAdjacencyList())    
    r = l1.symmetric_difference(l2)
    
    return r

#-----------------------------------------------------------------------
def test1():
  assert str(CNode("x")) == "x"

  g = CGraph()
  n1 = CNode("a")
  n2 = CNode("b")
  n3 = CNode("c")
  n4 = CNode("d")
  
  g.addEdge(n1, n2)
  g.addEdge(n1, n3)
  g.addEdge(n2, n4)
  g.addEdge(n3, n4)
  
  print "Printing a graph with 4 nodes"
  print g
  
  print "Searching path between n1 and n1"
  print g.searchPath(n1, n1)
  print "Searching path between n1 and n2"
  print g.searchPath(n1, n2)
  print "Searching path between n1 and n4"
  print g.searchPath(n1, n4)

  print "Creating a graph with 6 nodes"
  g = CGraph()
  a = CNode("a")
  b = CNode("b")
  c = CNode("c")
  d = CNode("d")
  e = CNode("e")
  f = CNode("f")
  
  g.addEdge(a, b)
  g.addEdge(b, c)
  g.addEdge(c, a)
  g.addEdge(d, e)
  g.addEdge(e, f)
  print "1# Searching a path between a and f"
  print g.searchPath(a, f)

  g.addEdge(c, d)
  print "2# Searching a path between a and f"
  print g.searchPath(a, f)
  
  g.addEdge(b, f)
  g.addEdge(c, f)
  g.addEdge(a, e)
  print "Searching all paths between a and f"
  print list(g.searchAllPaths(a, f))
  
  print "Searching the shortest path between a and f"
  print g.searchShortestPath(a, f)
  
  print "Clearing the graph"
  g.clear()
  print g

#-----------------------------------------------------------------------
def test2():
  #print "Creating 2 graphs with 3 and 5 nodes"
  a = CNode("a")
  b = CNode("b")
  c = CNode("c")
  n = CNode("n")
  x = CNode("x")
  y = CNode("y")

  g1 = CGraph()
  g2 = CGraph()

  g1.addEdge(a, b)
  g1.addEdge(a, c)

  g2.addEdge(a, n)
  g2.addEdge(n, y)
  g2.addEdge(b, x)
  g2.addEdge(x, y)

  #print "Graph 1"
  #print g1
  #print "Graph 2"
  #print g2
  #print "Adding graph 2 to graph 1"
  g1.addGraph(g2)

  #print "Resulting graph"
  #print g1
  
  #print "Adjacency list"
  print g1.toAdjacencyList()
  
  #print "Adjacency matrix"
  #print g1.nodes()
  print g1.toAdjacencyMatrix()

#-----------------------------------------------------------------------
def test3():
  a = CNode("a")
  b = CNode("b")
  c = CNode("c")
  n = CNode("n")
  x = CNode("x")
  y = CNode("y")

  g1 = CGraph()
  g2 = CGraph()

  g1.addEdge(a, b)
  g1.addEdge(a, c)

  g2.addEdge(a, n)
  g2.addEdge(n, y)
  g2.addEdge(b, x)
  g2.addEdge(x, y)

  g1.addGraph(g2)
  dot = g1.toDot()
  gml = g1.toGml()

#-----------------------------------------------------------------------
def randomGraph(totally=False):
  if totally:
    node_count = random.randint(0, 50)
  else:
    node_count = 50
  nodes = {}
  
  for x in range(node_count):
    name = "n%d" % x
    nodes[name] = CNode(name)
  
  g = CGraph()
  
  for x in nodes:
    for y in nodes:
      if random.randint(0, 10) == 0:
        g.addEdge(nodes[x], nodes[y])

  print g.toDot()

#-----------------------------------------------------------------------
def randomGraph2():
  node_count = random.randint(0, 50)
  nodes = {}
  
  for x in range(node_count):
    name = "n%d" % x
    nodes[name] = CNode(name)
  
  g = CGraph()
  
  for x in nodes:
    for y in nodes:
      if random.randint(0, 1) == 1:
        g.addEdge(nodes[x], nodes[y])

  for i in range(100):
    n1 = random.choice(nodes.keys())
    n2 = random.choice(nodes.keys())
    
    #print "Searching a path between %s and %s in a %d nodes graph" % (n1, n2, node_count)
    path = g.searchPath(n1, n2)
    if path:
      print "Path found between %s and %s in a %d nodes graph" % (n1, n2, node_count)
      print path

#-----------------------------------------------------------------------
def testRandomGraph():
  node_count = random.randint(2, 20)
  nodes = {}
  
  g = CGraph()
  
  for x in range(node_count):
    name = "n%d" % x
    nodes[name] = CNode(name)

  for x in nodes:
    for y in nodes:
      if random.randint(0, 4) == 1:
        g.addEdge(nodes[x], nodes[y])

  print "Graph"
  print g
  print
  print "Searching paths"
  for n1 in g.nodes():
    if g.has_key(n1):
      for n2 in g.d[n1]:
        print n1, n2
        print "Shortest", g.searchShortestPath(n1, n2)
        print "Longest", g.searchLongestPath(n1, n2)
        print "All paths: Total %d" % len(list(g.searchAllPaths(n1, n2)))

#-----------------------------------------------------------------------
def testIsSubgraph():
  """
  Graph 1
         A
        / \
         B   C
        / \ / \
       D  E F  G
  
  Graph 2
         A
        / 
         B
        / \
       D  E
  """

  a = CNode("a")
  b = CNode("b")
  c = CNode("c")
  d = CNode("d")
  e = CNode("e")
  f = CNode("f")
  g = CNode("g")

  g1 = CGraph()
  g1.addEdge(a, b)
  g1.addEdge(a, c)
  g1.addEdge(b, d)
  g1.addEdge(b, e)
  g1.addEdge(c, f)
  g1.addEdge(c, g)

  g2 = CGraph()
  print g2
  g2.addEdge(a, b)
  g2.addEdge(b, d)
  g2.addEdge(b, e)

  print g1
  print "g", g2
  # Check if it's a subgraph
  assert g1.isSubgraph(g2) 
  
  # Change the graph and check again
  g2.addEdge(a, d)
  assert g1.isSubgraph(g2) == False

#-----------------------------------------------------------------------
def testRandomSubgraph():
  #import random

  node_count = random.randint(0, 10000)
  nodes = dict()
  
  for x in range(node_count):
    name = "n%d" % int(x)
    nodes[name] = CNode(name)
  
  g = CGraph()
  i = 0
  for x in nodes:
    for y in nodes:
      if random.randint(0, 1) == 1:
        g.addEdge(nodes[x], nodes[y])
      i += 1
      if i <= node_count/2:
        g1 = g
  
  assert g.isSubgraph(g1) == True

#-----------------------------------------------------------------------
def testOperations():
  a = CNode("a")
  b = CNode("b")
  c = CNode("c")
  d = CNode("d")
  e = CNode("e")
  f = CNode("f")
  g = CNode("g")

  g1 = CGraph()
  g1.addEdge(a, b)
  g1.addEdge(a, c)
  g1.addEdge(b, d)
  g1.addEdge(b, e)
  g1.addEdge(c, f)
  g1.addEdge(c, g)

  g2 = CGraph()
  g2.addEdge(a, b)
  g2.addEdge(b, d)
  g2.addEdge(b, e)
  
  g3 = CGraph()
  al = g1.intersect(g2)

  g3.fromAdjacencyList(al)
  print g3
  
  al = g1.union(g2)
  g3.clear()
  g3.addEdge(f, a)
  
  g3.fromAdjacencyList(al)
  print g3
  
  print g3.toAdjacencyMatrix()
  
  print g3.difference(g1)
  print g2.difference(g1)
  print g3.difference(g2)
  
  al1 = g1.union(g2)
  al2 = g2.union(g3)
  new_graph = CGraph()
  new_graph.fromAdjacencyList(al1)
  new_graph.fromAdjacencyList(al2)
  
  print new_graph

#-----------------------------------------------------------------------
def testNode():
  g = CGraph()
  n = g.node("kk")
  if not n:
    n = CNode("kk")
  
  g.addNode(n)

#-----------------------------------------------------------------------
def testDict():
  d = {"New node 49": ["New node 48", "2190"], "New node 48": ["New node 47", "2322"], "New node 39": ["New node 1", "New node 4"], "New node 72": ["New node 67", "New node 33"], "New node 41": ["New node 40", "262"], "New node 40": ["New node 39", "692"], "New node 43": ["New node 41", "2950"], "New node 42": ["New node 22", "4160"], "New node 45": ["New node 44", "3965"], "New node 44": ["New node 43", "2327"], "New node 47": ["New node 46", "1842"], "New node 46": ["New node 45", "183"], "New node 67": ["New node 17", "New node 31"], "New node 66": ["New node 53", "New node 35"], "New node 65": ["New node 55", "New node 34"], "New node 28": ["2031", "2386"], "New node 63": ["New node 56", "New node 52"], "New node 62": ["New node 50", "New node 37"], "New node 61": ["New node 29", "New node 60"], "New node 60": ["New node 59", "New node 32"], "New node 23": ["930", "4237"], "New node 22": ["1277", "2531"], "New node 21": ["3004", "2283"], "New node 20": ["668", "New node 3"], "New node 27": ["2347", "2698"], "New node 26": ["2808", "3532"], "New node 25": ["2433", "3801"], "New node 24": ["243", "596"], "New node 29": ["1540", "New node 11"], "New node 19": ["629", "4200"], "New node 32": ["2241", "3052"], "New node 73": ["New node 72", "New node 69"], "New node 69": ["New node 38", "New node 68"], "New node 5": ["4242", "2815"], "New node 68": ["New node 66", "New node 36"], "New node 74": ["New node 73", "New node 61"], "New node 58": ["New node 54", "New node 23"], "New node 59": ["New node 58", "New node 2"], "New node 56": ["New node 20", "New node 51"], "New node 57": ["New node 19", "New node 26"], "New node 54": ["New node 21", "New node 12"], "New node 55": ["New node 42", "New node 9"], "New node 52": ["New node 8", "New node 7"], "New node 53": ["New node 25", "New node 24"], "New node 50": ["New node 13", "New node 6"], "New node 51": ["New node 49", "3118"], "New node 12": ["2901", "734"], "New node 13": ["2478", "518"], "New node 10": ["3023", "1697"], "New node 11": ["1644", "3212"], "New node 16": ["2989", "3515"], "New node 71": ["New node 64", "New node 70"], "New node 14": ["1129", "544"], "New node 15": ["3810", "75"], "New node 30": ["New node 14", "2040"], "New node 31": ["New node 16", "3227"], "New node 18": ["New node 5", "2974"], "New node 33": ["New node 10", "1380"], "New node 34": ["1126", "2435"], "New node 35": ["New node 27", "1846"], "New node 36": ["3872", "3282"], "New node 37": ["4129", "New node 30"], "New node 8": ["3769", "3331"], "New node 9": ["3240", "1440"], "New node 75": ["New node 74", "New node 18"], "New node 1": ["2977", "2066"], "New node 2": ["3281", "4153"], "New node 3": ["705", "3958"], "New node 4": ["2226", "3089"], "New node 76": ["New node 75", "New node 62"], "New node 6": ["2130", "1792"], "New node 7": ["3187", "2497"], "New node 64": ["New node 28", "New node 63"], "New node 38": ["1753", "New node 15"], "New node 70": ["New node 57", "New node 65"], "New node 77": ["New node 76", "New node 71"], "New node 17": ["1031", "1368"]}

  g = CGraph()
  g.fromDict(d)
  print g.toDot()

#-----------------------------------------------------------------------
def testJson():
  d = {"New node 49": ["New node 48", "2190"], "New node 48": ["New node 47", "2322"], "New node 39": ["New node 1", "New node 4"], "New node 72": ["New node 67", "New node 33"], "New node 41": ["New node 40", "262"], "New node 40": ["New node 39", "692"], "New node 43": ["New node 41", "2950"], "New node 42": ["New node 22", "4160"], "New node 45": ["New node 44", "3965"], "New node 44": ["New node 43", "2327"], "New node 47": ["New node 46", "1842"], "New node 46": ["New node 45", "183"], "New node 67": ["New node 17", "New node 31"], "New node 66": ["New node 53", "New node 35"], "New node 65": ["New node 55", "New node 34"], "New node 28": ["2031", "2386"], "New node 63": ["New node 56", "New node 52"], "New node 62": ["New node 50", "New node 37"], "New node 61": ["New node 29", "New node 60"], "New node 60": ["New node 59", "New node 32"], "New node 23": ["930", "4237"], "New node 22": ["1277", "2531"], "New node 21": ["3004", "2283"], "New node 20": ["668", "New node 3"], "New node 27": ["2347", "2698"], "New node 26": ["2808", "3532"], "New node 25": ["2433", "3801"], "New node 24": ["243", "596"], "New node 29": ["1540", "New node 11"], "New node 19": ["629", "4200"], "New node 32": ["2241", "3052"], "New node 73": ["New node 72", "New node 69"], "New node 69": ["New node 38", "New node 68"], "New node 5": ["4242", "2815"], "New node 68": ["New node 66", "New node 36"], "New node 74": ["New node 73", "New node 61"], "New node 58": ["New node 54", "New node 23"], "New node 59": ["New node 58", "New node 2"], "New node 56": ["New node 20", "New node 51"], "New node 57": ["New node 19", "New node 26"], "New node 54": ["New node 21", "New node 12"], "New node 55": ["New node 42", "New node 9"], "New node 52": ["New node 8", "New node 7"], "New node 53": ["New node 25", "New node 24"], "New node 50": ["New node 13", "New node 6"], "New node 51": ["New node 49", "3118"], "New node 12": ["2901", "734"], "New node 13": ["2478", "518"], "New node 10": ["3023", "1697"], "New node 11": ["1644", "3212"], "New node 16": ["2989", "3515"], "New node 71": ["New node 64", "New node 70"], "New node 14": ["1129", "544"], "New node 15": ["3810", "75"], "New node 30": ["New node 14", "2040"], "New node 31": ["New node 16", "3227"], "New node 18": ["New node 5", "2974"], "New node 33": ["New node 10", "1380"], "New node 34": ["1126", "2435"], "New node 35": ["New node 27", "1846"], "New node 36": ["3872", "3282"], "New node 37": ["4129", "New node 30"], "New node 8": ["3769", "3331"], "New node 9": ["3240", "1440"], "New node 75": ["New node 74", "New node 18"], "New node 1": ["2977", "2066"], "New node 2": ["3281", "4153"], "New node 3": ["705", "3958"], "New node 4": ["2226", "3089"], "New node 76": ["New node 75", "New node 62"], "New node 6": ["2130", "1792"], "New node 7": ["3187", "2497"], "New node 64": ["New node 28", "New node 63"], "New node 38": ["1753", "New node 15"], "New node 70": ["New node 57", "New node 65"], "New node 77": ["New node 76", "New node 71"], "New node 17": ["1031", "1368"]}

  g = CGraph()
  g.fromDict(d)
  print g.toJson()

#-----------------------------------------------------------------------
def testAll():
  #test1()
  #test2()
  #test3()
  """randomGraph()
  randomGraph2()
  testRandomGraph()"""
  testIsSubgraph()
  #testNode()
  testRandomSubgraph()
  testOperations()
  print "Done!"

if __name__ == "__main__":
  #testAll()
  testDict()
