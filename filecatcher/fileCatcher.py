import datetime
import os

from filecatcher.listfiles import _ListFiles
from settings import VIRUS_TOTAL
from utils.utils import get_csv_writer, write_to_csv, process_size, record_sha256_logs, \
    process_sha256
from utils.utils_rawstring import sekoiamagic
import yaml
from filecatcher.modules.PE import _PE
from filecatcher.modules.intel import _Intel
from archives import _Archives


class _FileCatcher(object):
    def __init__(self, params):
        self.params = params
        self.systemroot = params['system_root']
        self.dirs = {i.split('|')[0]: i.split('|')[1] for i in params['fs']}
        self.mime_filter = params['mime_filter'].split(';')
        self.size_min = process_size(params['size_min'])
        self.size_max = process_size(params['size_max'])
        self.mime_zip = params['mime_zip'].split(';')
        self.computer_name = params['computer_name']
        self.output_dir = params['output_dir']
        self.zip = params['zip']
        self.zip_ext_file = params['zip_ext_file'].split(',')
        self.ext_file = params['ext_file'].split(',')
        self.logger = params['logger']
        self.compare = params['compare']
        self.filtered_certificates = yaml.load(params['filtered_certificates'])
        self.filtered_yara = yaml.load(params['filtered_yara'])
        self.zip_file=None
        if self.zip:
            self.zip_file = _Archives(self.output_dir + '\\' + self.computer_name + '_files_.zip',self.logger)

    def _list_files(self):
        pe = None
        yara_matching = None
        self.logger.warn('Dirs: ' + str(self.dirs) + 'to catch')
        for directory in self.dirs:
            directory = self._changeroot(directory)
            lst = _ListFiles(directory, self.logger)

            for f in lst.list_files(directory):
                if self.filtered_yara:
                    if not yara_matching:
                        yara_matching = _Intel(f, self.params)
                    else:
                        setattr(yara_matching, 'path', f)
                    rules = yara_matching.process()
                    if rules:
                        self.zip_file.record(f)
                        try:
                            yield f, str(rules), self._process_hash(f), 'yara', self._timestamp(f), os.stat(f).st_size == 0
                        except Exception as e:
                            yield f, str(rules), 'Permission denied', str(e), self._timestamp(f), os.stat(f).st_size == 0
                ext = os.path.splitext(f)[1][1:]
                if self._filtered_size(f):
                    mime_filter, mime_zip, mime = self._filtered_magic(f)

                    if self._is_PE(mime):
                        if self.filtered_certificates:
                            if not pe:
                                pe = _PE(f, self.params)
                                self.logger.debug("Create Singleton PE")
                            else:
                                setattr(pe, 'path', f)
                            if pe.process():
                                continue
                    self.logger.debug("Certificats Check")
                    zip_proc = False
                    if self.zip_file:
                        if self._filtered([mime_zip, self._filtered_ext(ext, self.zip_ext_file)]):
                            self.zip_file.record(f)
                            zip_proc = True
                    if self._filtered([mime_filter, self._filtered_ext(ext, self.ext_file)]):
                        try:
                            yield f, mime, self._process_hash(f), zip_proc, self._timestamp(f), os.stat(f).st_size == 0
                        except Exception as e:
                            yield f, mime, 'Permission denied', str(e), self._timestamp(f), os.stat(f).st_size == 0

    def _timestamp(self, f):
        t = os.path.getctime(f) 
        date_value = datetime.datetime.fromtimestamp(t)
        return date_value

    def _process_hash(self, f):
        if hasattr(self, 'vss') and self.vss:
            return self.vss.process_hash_value(f)
        else:
            return process_sha256(f)

    def _filtered_magic(self, f):
        try:
            mime = sekoiamagic(f)
            wildcard_mime_filter = mime in self.mime_filter
            wildcard_mime_zip = mime in self.mime_zip
            if "*" in self.mime_filter:
                wildcard_mime_filter = True
            if "*" in self.mime_zip:
                wildcard_mime_zip = True
            return wildcard_mime_filter, wildcard_mime_zip, mime
        except Exception as e:
            self.logger.error(e)
            return False, False, None

    def _filtered_size(self, f):
        try:
            return self.size_min <= os.stat(f).st_size <= self.size_max  # and self.size_max > os.stat(f).st_size
        except Exception as e:
            self.logger.error(e)
            return False

    def _filtered_ext(self, ext, filters):
        if '|EMPTY|' in filters:
            if len(ext) == 0:
                return True
        if '*' in filters:
            return True
        if 'all' in filters:
            return True
        else:
            return ext in filters

    def _filtered(self, items):
        if self.compare == 'AND':
            return all(items)
        if self.compare == 'OR':
            return any(items)
        return True

    def _is_PE(self, mime):
        if mime:
            return mime in self.params['pe_mime_type']
        else:
            return False

    def _check_depth(self, f, directory):
        if self.dirs[directory] == '*':
            return True
        return int(self.dirs[directory]) >= f[len(directory)+len(os.path.sep):].count(os.path.sep)

    def _csv_infos_fs(self, files):
        with open(self.output_dir + '\\' + self.computer_name + '_Filecatcher.csv', 'wb') as fw:
            csv_writer = get_csv_writer(fw)
            for f, mime, hashvalue, zip_value, datem, empty in files:
                if 'Permission denied' in hashvalue:
                    url_vt = 'not URL VT'
                else:
                    url_vt = unicode(VIRUS_TOTAL % hashvalue)
                write_to_csv([self.computer_name, 'Filecatcher', unicode(datem),
                              unicode(f), unicode(hashvalue), unicode(mime),
                              unicode(zip_value), unicode(empty), url_vt], csv_writer)
        record_sha256_logs(self.output_dir + '\\' + self.computer_name + '_Filecatcher.csv',
                           self.output_dir + '\\' + self.computer_name + '_sha256.log')
        self.zip_file.close()
