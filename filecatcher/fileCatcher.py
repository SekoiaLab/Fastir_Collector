import datetime
import os

from filecatcher.listfiles import _ListFiles
from settings import VIRUS_TOTAL
from utils.utils import get_csv_writer, get_json_writer,write_to_csv, write_to_json,process_size, record_sha256_logs, \
    process_hashes
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
        self.limit_days = params['limit_days']
        self.rand_ext = params['rand_ext']
        self.zip_file = None
        if self.zip:
            self.zip_file = _Archives(self.output_dir + '\\' + self.computer_name + '_files_.zip', self.logger)
        if 'destination' in params:
            self.destination = params['destination']

    def _list_files(self):
        pe = None
        yara_matching = None
        self.logger.warn('Dirs: ' + str(self.dirs) + 'to catch')
        for directory in self.dirs:
            shadow_directory = self._changeroot(directory)
            lst = _ListFiles(shadow_directory, self.logger)

            for f in lst.list_files(shadow_directory):
                zip_proc = False
                if self._filtered_by_date(f) and self._filtered_size(f) and self._check_depth(f,self.dirs[directory], shadow_directory):
                    if self.filtered_yara:
                        if not yara_matching:
                            yara_matching = _Intel(f, self.params)
                        else:
                            setattr(yara_matching, 'path', f)
                        rules = yara_matching.process()
                        if rules:
                            self.zip_file.record(f)
                            try:
                                md5, sha1, sha256 = self._process_hashes(f)
                                yield f, str(rules), md5, sha1, sha256, 'yara', self._get_creation_date(f), os.stat(
                                    f).st_size == 0
                            except Exception as e:
                                yield f, str(rules), 'N/A', 'N/A', 'N/A', str(e), self._get_creation_date(f), os.stat(
                                    f).st_size == 0


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

                    ext = os.path.splitext(f)[1][1:]
                    mime_filter, mime_zip, mime = self._filtered_magic(f)
                    if self.zip_file:
                        if self._filtered([mime_zip, self._filtered_ext(ext, self.zip_ext_file)]):
                            self.zip_file.record(f)
                            zip_proc = True
                    if self._filtered([mime_filter, self._filtered_ext(ext, self.ext_file)]):
                        try:
                            md5, sha1, sha256 = self._process_hashes(f)
                            yield f, mime, md5, sha1, sha256, zip_proc, self._get_creation_date(f), os.stat(
                                f).st_size == 0
                        except Exception as e:
                            yield f, mime, 'N/A', 'N/A', 'N/A', str(e), self._get_creation_date(f), os.stat(
                                f).st_size == 0
                else:
                    try:
                        self.logger.warn('file %s not cache by size %s or date %s' % (f, os.stat(f).st_size, self._get_modification_date(f)))
                    except Exception as e:
                        self.logger.error(e)
                        self.logger.error(f)

    def _get_creation_date(self, f):
        t = os.path.getctime(f)
        date_value = datetime.datetime.fromtimestamp(t)
        return date_value

    def _get_modification_date(self, f):
        t = os.path.getmtime(f)
        date_value = datetime.datetime.fromtimestamp(t)
        return date_value

    def _process_hashes(self, f):
        if hasattr(self, 'vss') and self.vss:
            return self.vss.process_hash_value(f)
        else:
            return process_hashes(f)

    def _filtered_by_date(self, f):
        if self.limit_days == 'unlimited':
            return True
        try:

            return (datetime.datetime.now() - self._get_modification_date(f)).days < int(self.limit_days)
        except Exception as e:
            self.logger.error(e)
            return True
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

    def _check_depth(self, f,depth, directory):
        if depth == '*':
            return True
        return int(depth) >= f[len(directory) + len(os.path.sep):].count(os.path.sep)

    def _get_url_VT(self,sha256):
        url_vt = None
        if 'N/A' in sha256:
            url_vt = 'not URL VT'
        else:
            url_vt = unicode(VIRUS_TOTAL % sha256)
        return url_vt

    def _csv_infos_fs(self, files):
        with open(self.output_dir + '\\' + self.computer_name + '_Filecatcher' + self.rand_ext, 'wb') as fw:
            csv_writer = get_csv_writer(fw)
            for f, mime, md5,sha1,sha256, zip_value, datem, empty in files:
                write_to_csv([self.computer_name, 'Filecatcher', unicode(datem),
                              unicode(f), unicode(md5), unicode(sha1), unicode(sha256), unicode(mime),
                              unicode(zip_value), unicode(empty), self._get_url_VT(sha256)], csv_writer)
        record_sha256_logs(self.output_dir + '\\' + self.computer_name + '_Filecatcher' + self.rand_ext,
                           self.output_dir + '\\' + self.computer_name + '_sha256.log')
        self.zip_file.close()

    def _json_infos_fs(self, files):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_Filecatcher.json' % self.computer_name),'wb') as fw:
                json_writer = get_json_writer(fw)
                header =['COMPUTER NAME','TYPE', 'DATE','PATH','MD5','SHA1','SHA256','MIMETYPE','ZIP',
                         'EMPTY','VT']
                for f, mime, md5, sha1, sha256, zip_value, datem, empty in files:
                    write_to_json(header,[self.computer_name, 'Filecatcher', unicode(datem),
                                  unicode(f), unicode(md5), unicode(sha1), unicode(sha256), unicode(mime),
                                  unicode(zip_value), unicode(empty), self._get_url_VT(sha256)], json_writer)
            self.zip_file.close()
