#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Cosa Nostra logging utilities
@author: joxean
"""

import os
import sys
import time
import _thread

from config import DEBUG

#-----------------------------------------------------------------------
def log(msg):
  print("[%s %d:%d] %s" % (time.asctime(), os.getpid(), _thread.get_ident(), msg))
  sys.stdout.flush()

#-----------------------------------------------------------------------
def debug(msg):
  if DEBUG:
    log(msg)
