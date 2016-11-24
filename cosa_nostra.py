#!/usr/bin/python

import os
import sys
import web
import json

from web import form
from hashlib import sha1
from urllib import quote_plus

from graphs import CGraph
from config import CN_USER, CN_PASS
from cn_query import q2w, seems_query
from cn_db import init_web_db, webpy_connect_db as connect_db

#-----------------------------------------------------------------------
urls = (
  '/', 'index',
  '/login', 'login',
  '/logout', 'logout',
  '/favicon.ico', 'favicon',
  '/config', 'config',
  '/samples', 'samples',
  '/clusters', 'clusters',
  '/view_cluster', 'view_cluster',
  '/update_cluster', 'update_cluster',
  '/view_cluster.json', 'view_cluster_json',
)

app = web.application(urls, globals())
render = web.template.render('templates/')
if web.config.get('_cn_session') is None:
  session = web.session.Session(app, web.session.DiskStore('cn-sessions'), {'user':None})
  web.config._cn_session = session
else:
  session = web.config._cn_session

register_form = form.Form(
  form.Textbox("username", description="Username"),
  form.Password("password", description="Password"),
  form.Button("submit", type="submit", description="Login"),
  validators = [
    form.Validator("All fields are mandatory", lambda i: i.username == "" or i.password == "")]
)

#-----------------------------------------------------------------------
# FUNCTIONS

#-----------------------------------------------------------------------
def create_schema(db):
  printing = db.printing
  db.printing = False

  sql = """create table if not exists config (
           id integer not null primary key autoincrement,
           name varchar(50),
           value varchar(255),
           description varchar(255));"""
  db.query(sql)

  sql = """create table if not exists samples (
           id integer not null primary key autoincrement,
           filename varchar(255),
           description varchar(255),
           format varchar(30),
           hash varchar(40),
           callgraph text,
           primes text,
           total_functions integer,
           clustered integer default '0',
           analysis_date varchar(255));"""
  db.query(sql)

  sql = """create table if not exists clusters (
           id integer not null primary key autoincrement,
           description text,
           generation_level integer,
           last_update varchar(255),
           graph text,
           samples text,
           min_funcs integer,
           max_funcs integer,
           dot text,
           tags text
           );"""
  db.query(sql)

  sql = """create index if not exists idx_cluster_samples
                                   on clusters(samples)"""
  db.query(sql)

  sql = """create index if not exists idx_cluster_desc
                                   on clusters(description)"""
  db.query(sql)

  sql = """ create index if not exists idx_samples_description
                                    on samples(description)"""
  db.query(sql)

  sql = """ create index if not exists idx_samples_filename
                                    on samples(filename)"""
  db.query(sql)

  sql = """ create index if not exists idx_samples_hash
                                    on samples(hash)"""
  db.query(sql)

  sql = """ create index if not exists idx_samples_composite1
                                    on samples(hash, description,
                                               filename)"""
  db.query(sql)

  db.printing = printing

#-----------------------------------------------------------------------
def open_db():
  db = init_web_db()
  if not 'schema' in session or session.schema is None:
    create_schema(db)
    session.schema = True
  return db

#-----------------------------------------------------------------------
# CLASSES

#-----------------------------------------------------------------------
class favicon: 
  def GET(self): 
    f = open("static/favicon.ico", 'rb')
    return f.read()

#-----------------------------------------------------------------------
class login:
  def POST(self):
    i = web.input(username="", password="")
    if i.username == "" or i.password == "":
      return render.error("Invalid username or password")
    elif i.username != CN_USER or sha1(i.password).hexdigest() != CN_PASS:
      return render.error("Invalid username or password")
    session.user = i.username
    return web.seeother("/")

#-----------------------------------------------------------------------
class index:
  def GET(self):
    if not 'user' in session or session.user is None:
      f = register_form()
      return render.login(f)
    return render.index()

#-----------------------------------------------------------------------
class logout:
  def GET(self):
    session.user = None
    del session.user
    return web.seeother("/")

#-----------------------------------------------------------------------
class config:
  def POST(self):
    if not 'user' in session or session.user is None:
      f = register_form()
      return render.login(f)

    i = web.input(anal_engine="", ida_path="", pyew_path="")
    if i.anal_engine == "" or (i.ida_path + i.pyew_path == ""):
      render.error("Invalid analysis engine, IDA path or Pyew path.")

    db = open_db()
    with db.transaction():
      sql = "select 1 from config where name = 'IDA_PATH'"
      res = list(db.query(sql))
      if len(res) > 0:
        sql = "update config set value = $value where name = 'IDA_PATH'"
      else:
        sql = "insert into config (name, value) values ('IDA_PATH', $value)"
      db.query(sql, vars={"value":i.ida_path})

      sql = "select 1 from config where name = 'PYEW_PATH'"
      res = list(db.query(sql))
      if len(res) > 0:
        sql = "update config set value = $value where name = 'PYEW_PATH'"
      else:
        sql = "insert into config (name, value) values ('PYEW_PATH', $value)"
      db.query(sql, vars={"value":i.pyew_path})

      sql = "select 1 from config where name = 'ANAL_ENGINE'"
      res = list(db.query(sql))
      if len(res) > 0:
        sql = "update config set value = $value where name = 'ANAL_ENGINE'"
      else:
        sql = "insert into config (name, value) values ('ANAL_ENGINE', $value)"
      db.query(sql, vars={"value":i.anal_engine})

    return web.redirect("/config")

  def GET(self):
    if not 'user' in session or session.user is None:
      f = register_form()
      return render.login(f)

    db = open_db()
    sql = """select name, value
               from config
              where name in ('ANAL_ENGINE', 'PYEW_PATH', 'IDA_PATH')"""
    res = db.query(sql)

    anal_engine = ""
    ida_path = ""
    pyew_path = ""
    for row in res:
      name, value = row.name, row.value
      if name == 'PYEW_PATH':
        pyew_path = value
      elif name == 'IDA_PATH':
        ida_path = value
      elif name == 'ANAL_ENGINE':
        anal_engine = value

    return render.config(anal_engine, ida_path, pyew_path)

#-----------------------------------------------------------------------
class samples:
  def GET(self):
    if not 'user' in session or session.user is None:
      f = register_form()
      return render.login(f)
    
    i = web.input(show_all=0, q="")

    what = "id, filename, format, description, hash, total_functions,"
    what += "analysis_date, clustered"
    where = "1 = 1"
    order = "id desc"

    q = ""
    i.q = i.q.strip(" ").replace("\n", "")
    if i.q != "":
      q = i.q
      if seems_query(q):
        fields = ["id", "filename", "format", "description", "hash",
                  "total_functions", "analysis_date", "clustered"]

        try:
          query = q2w(fields, i.q)
        except:
          return render.error(sys.exc_info()[1])
      else:
        query = "hash = %s or filename like %s or description like %s"
        i.q = i.q.replace("'", "")
        rq = repr(str(i.q))
        rq_like = repr("%" + str(i.q) + "%")
        query %= (rq, rq_like, rq_like)

      if query.strip(" ") != "":
        where += " and %s" % query

    db = open_db()
    sql = "select count(*) total from samples"
    if q != "":
      sql += " where %s" % query
    ret = db.query(sql)
    total = 0
    for row in ret:
      total = row["total"]

    limit = 15
    if i.show_all == "1":
      limit = int(total)

    ret = db.select("samples", what=what, where=where, order=order, \
                               limit=limit)
    i = 0
    results = []
    for row in ret:
      row["filename"] = os.path.basename(row["filename"])
      if row["filename"] == row["hash"]:
        row["filename"] = "<Same as SHA1 hash>"
      results.append(row)

      i += 1
      if i > limit:
        break

    do_show_all = int(limit == int(total))
    return render.samples(results, total, do_show_all, q, quote_plus(q))

#-----------------------------------------------------------------------
class update_cluster:
  def POST(self):
    if not 'user' in session or session.user is None:
        f = register_form()
        return render.login(f)

    i = web.input(id=None, description=None)
    cluster_id = i.id
    if cluster_id is None:
      return render.error("No cluster id specified.")

    if not cluster_id.isdigit():
      return render.error("Invalid number.")
    cluster_id = int(cluster_id)

    desc = i.description
    vars = {"id":cluster_id}

    db = open_db()
    db.update('clusters', vars=vars, where="id = $id", description=desc)

    raise web.seeother("/view_cluster?id=%d" % cluster_id)

#-----------------------------------------------------------------------
class view_cluster:
  def GET(self):
    if not 'user' in session or session.user is None:
      f = register_form()
      return render.login(f)

    i = web.input(id=None)
    cluster_id = i.id
    if cluster_id is None:
      return render.error("No cluster id specified.")

    if not cluster_id.isdigit():
      return render.error("Invalid number.")

    try:
      cluster_id = int(cluster_id)
    except:
      return render.error(sys.exc_info()[1])

    db = open_db()

    what="*"
    where="id = $id"
    sql_vars = {"id":cluster_id}
    ret = db.select("clusters", vars=sql_vars, where=where, what=what)
    rows = list(ret)
    if len(rows) == 0:
      return render.error("Cluster %d not found." % cluster_id)
    elif len(rows) > 2:
      return render.error("Duplicate cluster (%d) found!" % cluster_id)

    return render.view_cluster(rows[0])

#-----------------------------------------------------------------------
def get_sample_data(name):
  db = open_db()
  where = "id = $id"
  what = "description, hash, analysis_date, filename, total_functions"
  sql_vars = {"id":int(name)}
  ret = db.select("samples", vars=sql_vars, what=what, where=where)
  rows = list(ret)
  if len(rows) == 0:
    raise Exception("Sample not found.")
  
  return rows[0]

#-----------------------------------------------------------------------
def create_json_node(name):
  d = {"name":name}
  return d

#-----------------------------------------------------------------------
def get_json_children_nodes(g, label):
  d = g.d
  l = []
  node = g.node(label)
  if not node in d:
    return l

  for child in d[node]:
    name = child.name
    if child.name.isdigit():
      data = get_sample_data(child.name)
      if data["description"] is None or data["description"] == "":
        data["description"] = os.path.basename(data["filename"])
    else:
      data = {"description":""}

    name = data["description"]
    tmp = create_json_node(name)
    if len(data) > 1:
      tmp["hash"] = data["hash"]
      tmp["date"] = data["analysis_date"]
      tmp["filename"] = data["filename"]
      tmp["functions"] = data["total_functions"]
    else:
      tmp["hash"] = tmp["date"] = tmp["filename"] = tmp["functions"] = ""
    children = get_json_children_nodes(g, child.name)
    if len(children) > 0:
      tmp["children"] = children
    l.append(tmp)

  return l

#-----------------------------------------------------------------------
def graph2json(g):
  root = None
  for node in g.nodes():
    if not g.hasParents(node):
      root = node.name
      break

  d = create_json_node("Root")
  children = get_json_children_nodes(g, root)
  d["children"] = children
  return json.dumps(d) #children

#-----------------------------------------------------------------------
class view_cluster_json:
  def GET(self):
    if not 'user' in session or session.user is None:
      f = register_form()
      return render.login(f)

    i = web.input(id=None)
    if i.id is None or not i.id.isdigit():
      return render.error("No cluster id specified or invalid one.")

    db = open_db()
    where = "id = $id"
    sql_vars = {"id":int(i.id)}
    ret = db.select("clusters", what="graph", vars=sql_vars, where=where)
    rows = list(ret)
    if len(rows) == 0:
      return render.error("Invalid cluster id.")

    g_text = rows[0]["graph"]
    g = CGraph()
    g.fromDict(json.loads(g_text))
    json_graph = graph2json(g)
    return json_graph

#-----------------------------------------------------------------------
class clusters:
  def GET(self):
    if not 'user' in session or session.user is None:
      f = register_form()
      return render.login(f)

    i = web.input(show_all=0)

    db = open_db()
    sql = "select count(*) total from clusters"
    ret = db.query(sql)
    total = 0
    for row in ret:
      total = row["total"]

    limit = 25
    if int(i.show_all) == 1:
      limit = total

    ret = db.select("clusters", order="id desc", limit=limit)
    rows = list(ret)
    return render.clusters(rows, total, json.loads)

if __name__ == "__main__": 
  app.run()
