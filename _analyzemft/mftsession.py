#!/usr/bin/env python

# Author: David Kovar [dkovar <at> gmail [dot] com]
# Name: analyzeMFT.py
#
# Copyright (c) 2010 David Kovar. All rights reserved.
# This software is distributed under the Common Public License 1.0
#
# Date: May 2013
#

VERSION = "v2.0.11"

import sys
import csv
import os
from optparse import OptionParser
import mft
from utils.utils import get_json_writer, write_to_json
SIAttributeSizeXP = 72
SIAttributeSizeNT = 48


class _MftSession:
    'Class to describe an entire MFT processing session'

    def __init__(self, logger, filename=None, output=None, json_output=False):
        self.mft = {}
        self.fullmft = {}
        self.folders = {}
        self.debug = False
        self.mftsize = 0
        self.logger = logger
        self.filename = filename
        self.output = output
        self.logger.info('Analyzing MFT : ' + filename)
        self.json = True
    def open_files(self):
        try:
            self.file_mft = open(self.filename, 'rb')
        except:
            self.logger.error("Unable to open file: %s" % self.filename)
            sys.exit()

        try:
            if not self.json:
                self.file_csv = csv.writer(open(self.output, 'wb'), delimiter='|', dialect=csv.excel, quoting=1)
            else:
                self.json_writer = get_json_writer(open(self.output,'wb'))

        except (IOError, TypeError):
            self.logger.error("Unable to open file: %s" % self.output)
            sys.exit()


    def sizecheck(self):
        # The number of records in the MFT is the size of the MFT / 1024
        self.mftsize = long(os.path.getsize(self.filename)) / 1024

        self.logger.info('There are %d records in the MFT' % self.mftsize)


    def process_mft_file(self):
        self.sizecheck()

        self.build_filepaths()

        # reset the file reading
        self.num_records = 0
        self.file_mft.seek(0)
        raw_record = self.file_mft.read(1024)

        if self.output != None and not self.json:
            self.file_csv.writerow(mft.mft_to_csv(None, True))
        elif self.output != None and self.json:
            self.header = mft.mft_to_csv(None, True)

        while raw_record != "":
            record = {}
            record = mft.parse_record(raw_record, False)

            record['filename'] = self.mft[self.num_records]['filename']

            self.do_output(record)

            self.num_records = self.num_records + 1

            if record['ads'] > 0:
                for i in range(0, record['ads']):
                    record_ads = record.copy()
                    record_ads['filename'] = record['filename'] + ':' + record['data_name', i]
                    self.do_output(record_ads)

            raw_record = self.file_mft.read(1024)

    def do_output(self, record):
        if self.output != None and not self.json:
            self.file_csv.writerow(mft.mft_to_csv(record, False))
        elif self.output != None and self.json:
            write_to_json(self.header, mft.mft_to_csv(record, False), self.json_writer)
        if self.num_records % (self.mftsize / 5) == 0 and self.num_records > 0:
            self.logger.info('Building MFT: {0:.0f}'.format(100.0 * self.num_records / self.mftsize) + '%')


    def plaso_process_mft_file(self):
        # TODO - Add ADS support ....
        self.build_filepaths()

        # reset the file reading
        self.num_records = 0
        self.file_mft.seek(0)
        raw_record = self.file_mft.read(1024)

        while raw_record != "":
            record = {}
            record = mft.parse_record(raw_record, False)

            record['filename'] = self.mft[self.num_records]['filename']

            self.fullmft[self.num_records] = record

            self.num_records = self.num_records + 1

            raw_record = self.file_mft.read(1024)

    def build_filepaths(self):
        # reset the file reading
        self.file_mft.seek(0)

        self.num_records = 0

        # 1024 is valid for current version of Windows but should really get this value from somewhere
        raw_record = self.file_mft.read(1024)
        while raw_record != "":

            record = {}
            minirec = {}
            record = mft.parse_record(raw_record, False)

            minirec['filename'] = record['filename']
            minirec['fncnt'] = record['fncnt']
            if record['fncnt'] == 1:
                minirec['par_ref'] = record['fn', 0]['par_ref']
                minirec['name'] = record['fn', 0]['name']
            if record['fncnt'] > 1:
                minirec['par_ref'] = record['fn', 0]['par_ref']
                for i in (0, record['fncnt'] - 1):
                    # print record['fn',i]
                    if (record['fn', i]['nspace'] == 0x1 or record['fn', i]['nspace'] == 0x3):
                        minirec['name'] = record['fn', i]['name']
                if (minirec.get('name') == None):
                    minirec['name'] = record['fn', record['fncnt'] - 1]['name']

            self.mft[self.num_records] = minirec

            if self.num_records % (self.mftsize / 5) == 0 and self.num_records > 0:
                self.logger.info('Building Filepaths: {0:.0f}'.format(100.0 * self.num_records / self.mftsize) + '%')

            self.num_records = self.num_records + 1

            raw_record = self.file_mft.read(1024)

        self.gen_filepaths()


    def get_folder_path(self, seqnum):
        if self.debug: print "Building Folder For Record Number (%d)" % seqnum

        if seqnum not in self.mft:
            return 'Orphan'

        # If we've already figured out the path name, just return it
        if (self.mft[seqnum]['filename']) != '':
            return self.mft[seqnum]['filename']

        try:
            # if (self.mft[seqnum]['fn',0]['par_ref'] == 0) or (self.mft[seqnum]['fn',0]['par_ref'] == 5):# There should be no seq number 0, not sure why I had that check in place.
            if (self.mft[seqnum]['par_ref'] == 5):  # Seq number 5 is "/", root of the directory
                self.mft[seqnum]['filename'] = '/' + self.mft[seqnum]['name']
                return self.mft[seqnum]['filename']
        except:  # If there was an error getting the parent's sequence number, then there is no FN record
            self.mft[seqnum]['filename'] = 'NoFNRecord'
            return self.mft[seqnum]['filename']

        # Self referential parent sequence number. The filename becomes a NoFNRecord note
        if (self.mft[seqnum]['par_ref']) == seqnum:
            if self.debug: print "Error, self-referential, while trying to determine path for seqnum %s" % seqnum
            self.mft[seqnum]['filename'] = 'ORPHAN/' + self.mft[seqnum]['name']
            return self.mft[seqnum]['filename']

        # We're not at the top of the tree and we've not hit an error
        parentpath = self.get_folder_path((self.mft[seqnum]['par_ref']))
        self.mft[seqnum]['filename'] = parentpath + '/' + self.mft[seqnum]['name']

        return self.mft[seqnum]['filename']


    def gen_filepaths(self):
        for i in self.mft:

            # if filename starts with / or ORPHAN, we're done.
            #			else get filename of parent, add it to ours, and we're done.

            # If we've not already calculated the full path ....
            if (self.mft[i]['filename']) == '':
                if ( self.mft[i]['fncnt'] > 0 ):
                    self.get_folder_path(i)
                    # self.mft[i]['filename'] = self.mft[i]['filename'] + '/' + self.mft[i]['fn',self.mft[i]['fncnt']-1]['name']
                    # self.mft[i]['filename'] = self.mft[i]['filename'].replace('//','/')
                    if self.debug: print "Filename (with path): %s" % self.mft[i]['filename']
                else:
                    self.mft[i]['filename'] == 'NoFNRecord'
