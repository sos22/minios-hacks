#! /usr/bin/env python

import sys

print "static const unsigned char %s[] = \"" % sys.argv[1],
while True:
    b = sys.stdin.read(1)
    if b == "":
        break
    sys.stdout.write("\\x%02x" % (ord(b)))
print "\";"
