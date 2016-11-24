#!/usr/bin/env python

#-----------------------------------------------------------------------
# Configuration for Cosa Nostra
#-----------------------------------------------------------------------
DEBUG=False
CN_USER="admin"
CN_PASS="048920dedfe36c112d74dc8108abb4db5185a918"

#-----------------------------------------------------------------------
# Configuration for Pyew's batch
#-----------------------------------------------------------------------

# Perform code analysis by default
CODE_ANALYSIS = True
# And do "deep code analysis" also by default
DEEP_CODE_ANALYSIS = True
# Do not set a timeout
CONFIG_ANALYSIS_TIMEOUT = 0

# Do not load neither a database nor plugins
PLUGINS_PATH  = "."
DATABASE_PATH = "."

# And disable this (buggy) heuristic
ANALYSIS_FUNCTIONS_AT_END=False
