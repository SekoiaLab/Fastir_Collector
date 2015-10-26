from petools.peparser import PeParser
from base_modules import _Base_Modules
from ctypes import *
import sys


class _PE(_Base_Modules):
    def __init__(self, path, params):
        super(_PE, self).__init__(path, params)
        self.hdll = windll.checksignfromcat
        self.beginfunc = self.hdll.BeginProcessFile
        self.beginfunc.argtypes = [c_wchar_p]
        self.beginfunc.restype = c_int
        self.countfunc = self.hdll.GetCertificatesCount
        self.countfunc.argtypes = [c_int]
        self.countfunc.restype = c_int
        self.issuerfunc = self.hdll.GetCertificateIssuer
        self.issuerfunc.argtypes = [c_int, c_int]
        self.issuerfunc.restype = POINTER(c_wchar_p)
        self.subjectfunc = self.hdll.GetCertificateSubject
        self.subjectfunc.argtypes = [c_int, c_int]
        self.subjectfunc.restype = POINTER(c_wchar_p)
        self.endfunc = self.hdll.EndProcessFile
        self.endfunc.argtypes = [c_int]
        self.endfunc.restype = c_int
        self.cert_filtered_issuer = self.params['cert_filtered_issuer'].split('|')
        self.cert_filtered_subject = self.params['cert_filtered_subject'].split('|')

    def process(self):
        return self.filtered_certificates()

    def _imphash(self):
        pass

    def _pehash(self):
        pass

    def get_certificates(self):
        # pe = PeParser(self.path)
        # issuer_value = ''
        # subject_value = ''
        # if pe.signature:
        #     issuer_value = pe.signature.getissuer()
        #     subject_value = pe.signature.getsubject()
        # else:
        #     pe.unmap()
        #     return None, None
        # return issuer_value,subject_value

        issuer_value = ''
        subject_value = ''

        handle = 0
        try:
            try:
                handle = self.beginfunc(self.path)

                if handle != 0:
                    count = self.countfunc(handle)
                    for index in xrange(count):
                        issuer = self.issuerfunc(handle, index)
                        subject = self.subjectfunc(handle, index)
                        issuer_value += ' %s' % wstring_at(issuer)
                        subject_value += ' %s' % wstring_at(subject)

            except WindowsError as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                self.params['logger'].error('Windows Error parsing with Catalog: %s line %s' % (self.path, exc_tb.tb_lineno))
                self.params['logger'].error(str(e))
                self.endfunc(handle)
            if len(issuer_value) == 0 and len(subject_value) == 0:
                try:
                    pe = PeParser(self.path)

                    issuer_value = ''
                    subject_value = ''
                    if pe.signature:
                        issuer_value = pe.signature.getissuer()
                        subject_value = pe.signature.getsubject()
                        pe.unmap()
                        #print issuer_value
                        #print subject_value
                    else:
                        pe.unmap()
                        return None, None
                except WindowsError as e:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    self.params['logger'].error('Windows Error parsing with pe-tools: %s line %s' % (self.path, exc_tb.tb_lineno))
                    self.params['logger'].error(str(e))
                    return None, None

        except WindowsError as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.params['logger'].error('Windows Error parsing: %s line %s' % (self.path, exc_tb.tb_lineno))
            self.params['logger'].error(str(e))
            return None, None
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.params['logger'].error('Error parsing: %s line %s' % (self.path, exc_tb.tb_lineno))
            self.params['logger'].error(str(e))
            return None, None

        return issuer_value, subject_value

    def filtered_certificates(self):
        issuer, subject = self.get_certificates()
        self.params['logger'].debug('Issuer: %s Subject: %s' % (issuer,subject))
        if issuer and subject:
            for i in self.cert_filtered_issuer:
                if i in issuer:
                    return True
            for s in self.cert_filtered_subject:
                if s in subject:
                    return True
        else:
            return False
