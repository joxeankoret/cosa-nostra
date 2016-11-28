# Cosa Nostra

Cosa Nostra is an open source software clustering toolkit with a focus on malware analysis. It can create phylogenetic trees of binary malware samples that are structurally similar. It was initially released during SyScan360 Shanghai (2016).

# Getting started

## Required 3rd party tools

In order to use Cosa Nostra you will need the source code, of course, a 2.7 version of Python, as well as one of the following tools in order to perform code analysis:

 * [Pyew](http://github.com/joxeankoret/pyew) Written in Python, it supports analysis of PE, ELF, Bios and Boot files for x86 or x86_64.
 * [IDA](http://www.hex-rays.com) Written in C++. It supports analysing a plethora of executable types that you probably never even heard about. Commercial product.
 * [Radare2](http://rada.re) Written in pure C. Same as with IDA, with support for extremely rare CPUs and binary formats. Also, it's open source!

## Analysing binaries

Once you have installed any of the previously mentioned tools you will need to use the appropriate batch tool to analyse the malware samples, like in the example bellow:

```
$ cd $COSA_NOSTRA_DIR
$ python r2_batch.py example.exe
```

Or

```
$ cd $COSA_NOSTRA_DIR
$ python pyew_batch.py example.exe
```

Or

```
$ cd $COSA_NOSTRA_DIR
$ /path/to/idaq -B -A -Sida_batch.py example.exe
```

### Automating the Analysis of a Malware Dataset

The easiest way to analyse a malware dataset is by simply running a command like the following example:

```
$ find /your/malware/dataset/path -type f -exec python r2_batch.py {} ';'
```

It can be done in parallel by using the "GNU Parallel" tool, as in the following example:

```
$ find /your/malware/dataset/path -type f | parallel -j 8 python pyew_batch.py {}
```

In the example above, it will launch a total of 8 pyew_batch processes in parallel.

## Database configuration

After the malware samples are analysed, if the analysis was successful, the call graph data for each sample will be stored in, by default, one SQLite database named "db.sqlite". You can configure the database name, path, database system, etc... by editing the file $COSA_NOSTRA_DIR/, as shown bellow:

```
$ cat config.cfg 
########################################################################
# Configuration for SQLite3
########################################################################
[database]
dbn=sqlite
# Database name
db=db.sqlite
```

If you prefer to use, say, a MySQL database system, you can configure it in config.cfg by putting the following configuration sections with the appropriate values for your setup:

```
########################################################################
# Example configuration for MySQL
########################################################################

[database]
dbn=mysql
# Database hostname or IP address
host=localhost
# Database name
db=db_name
# Database username
user=username
# Database password
pw=password
```

## Clusterization of malware samples

This is the step that will take more time. Once you have analysed all the malware samples from your datasets and the call graph signatures, corresponding prime numbers, etc... are calculated and stored in the database, the next step is to find cluster. The tool for doing so is called "cn_clusterer.py". It will make use of the same database configuration file ($COSA_NOSTRA_DIR/config.cfg) in order to extract the call graph signatures for the analysed samples. Running it as simple as doing the following:

```
$ cd $COSA_NOSTRA_DIR
$ ./cn_clusterer.py
(...)
Calculating difference matrix for 2357, iteration 5540280 out of 7507600 (4858784 matches, 600144 cache misses)
Calculating difference matrix for 2354, iteration 5543020 out of 7507600 (4861293 matches, 600373 cache misses)
Calculating difference matrix for 471, iteration 5545760 out of 7507600 (4863903 matches, 600373 cache misses)
(...)
Making tree for group with 59 sample(s), iteration 0 out of 256
Making tree for group with 393 sample(s), iteration 1 out of 256
Making tree for group with 1347 sample(s), iteration 2 out of 256
(...)
[Wed Nov  2 13:37:12 2016 2830:140561185462080] Creating unnamed cluster...
[Wed Nov  2 13:37:12 2016 2830:140561185462080] Creating cluster with name u'Win.Trojan.Skylock-4'...
[Wed Nov  2 13:37:12 2016 2830:140561185462080] Creating cluster with name u'Win.Downloader.133181-1'...
[Wed Nov  2 13:37:12 2016 2830:140561185462080] Creating cluster with name u'Win.Trojan.Agent-1213378'...
[Wed Nov  2 13:37:13 2016 2830:140561185462080] Done processing phylogenetic trees!
[Wed Nov  2 13:37:13 2016 2830:140561185462080] Done
```

When the process finishes, clusters grouping the analysed malware samples will be created in the specified database.

## Watching clusters: the web GUI

The last step is to launch the web.py based Web application and logging in:

```
$ cd $COSA_NOSTRA_DIR
$ python cosa_nostra.py [optional port to listen to]
http://0.0.0.0:YOURPORT/
```

Then, open a browser and navigate to the address printed out by cosa_nostra.py. A login form will be displayed asking for a username and password. By default, it's "admin/cosanostra". You can change it in the file $COSA_NOSTRA_DIR/config.py:

```
$ cat config.py
#!/usr/bin/env python

#-----------------------------------------------------------------------
# Configuration for Cosa Nostra
#-----------------------------------------------------------------------
DEBUG=False
CN_USER="admin"
# SHA1 hash of the password "cosanostra", change to the SHA1 hash of
# whatever password you prefer.
CN_PASS="048920dedfe36c112d74dc8108abb4db5185a918"
(...)
```

Once you're logged in you can select from the left panel one the following options:

 * Samples: See the samples in the current database.
 * Clusters: See the list of clusters that Cosa Nostra found for the given datasets.

In the "Clusters" view, one can select different clusters and view a hierarchical graph of the discovered malware family.

### Screenshots

List of clusters as shown in Cosa Nostra:

![List of clusters as shown in Cosa Nostra](
https://github.com/joxeankoret/cosa-nostra/raw/master/screenshots/clusters-list.png)

A small cluster of Trojan.Backspace-1 (name by ClamAV):

![A small cluster of Trojan.Backspace-1, name by ClamAV](https://github.com/joxeankoret/cosa-nostra/blob/master/screenshots/cluster-trojan-backspace.png)

A small cluster of MiniDukes:

![A small cluster of MiniDukes](https://github.com/joxeankoret/cosa-nostra/blob/master/screenshots/small-cluster-miniduke.png)

A cluster of Kazy/Bifroses:

![A cluster of Kazy/Bifroses](https://github.com/joxeankoret/cosa-nostra/blob/master/screenshots/kazi-bifrose-cluster.png)

A small part of a really big cluster of FannyWorms:

![A small part of a really big cluster of FannyWorms](https://github.com/joxeankoret/cosa-nostra/blob/master/screenshots/big-cluster-fannyworm.png)
