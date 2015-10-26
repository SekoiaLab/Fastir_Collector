# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import os


class _ListFiles(object):
    def __init__(self, root, logger, sep='\\'):
        self.root = root
        self.list_file = []
        self.sep = sep
        self.files = []
        self.logger = logger

    def list_files(self, dircurrent):
        for dirName, subdirList, fileList in os.walk(dircurrent, topdown=False):
            for fname in fileList:
                yield os.path.join(dirName, fname)
