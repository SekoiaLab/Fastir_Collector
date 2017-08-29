import ConfigParser
import os.path

"""
Placeholder class to enable conf fallbacks transparently for the rest of the application.
"""

class CustomConf:
    def __init__(self, filepaths):
        self.configs = list()
        for fp in filepaths:
            if os.path.isfile(fp):
                conf = ConfigParser.ConfigParser(allow_no_value=True)
                conf.readfp(open(fp))
                self.configs.append(conf)

        defaults = dict()

        # Default is a dict of dict containing the fallback options
        defaults['profiles'] = {
            'packages': 'fast'
        }
        defaults['extension'] = {
            'random': 'False'
        }
        defaults['dump'] = {
            'dump': 'mft,ram,mbr,registry',
            'mft_export': 'True'
        }
        defaults['registry'] = {
            'custom_registry_keys': 'HKCU\SOFTWARE\Locky',
            'registry_recursive': 'False',
            'get_autoruns': 'True'
        }
        defaults['output'] = {
            'type': 'csv',
            'destination': 'local',
            'dir': 'output',
            'share_dir': 'fastir_output',
            'excel': 'False',
        }
        defaults['filecatcher'] = {
            'all_users': 'True',
            'path': '%USERPROFILE%/AppData|*',
            'mime_filter': 'application/msword;application/octet-stream;application/x-archive;application/x-ms-pe;'
                           'application/x-ms-dos-executable;application/x-lha;application/x-dosexec;application/x-elc;'
                           'application/x-executable,statically linked, stripped;application/x-gzip;application/x-object,'
                           'not stripped;application/x-zip;text/html;text/rtf;text/xml;UTF-8 Unicode HTML document text,'
                           'with CRLF line terminators;UTF-8 Unicode HTML document text, with very long lines, with CRLF, LF line terminators',
            'mime_zip': 'application/x-ms-pe;application/x-ms-dos-executable;application/x-dosexec;application/x-executable, statically linked, stripped',
            'compare': 'AND',
            'size_min': '1k',
            'size_max': '100M',
            'ext_file': '*',
            'zip_ext_file': '*',
            'zip': 'True',
            'limit_days': 'unlimited'
        }
        defaults['modules'] = {
            'pe': None,
            'yara': None
        }
        defaults['pe'] = {
            'pe_mime_type': 'application/x-ms-pe;application/x-ms-dos-executable;application/x-dosexec;application/x-executable, statically linked, stripped',
            'filtered_certificates': 'True',
            'cert_filtered_issuer': 'issuer;O=Microsoft Corporation|Microsoft Time-Stamp PCA|Microsoft Time-Stamp PCA Microsoft Windows Verification PCA',
            'cert_filtered_subject': 'subject;O=Microsoft Corporation|Microsoft Time-Stamp Service|Microsoft Time-Stamp Service Microsoft Windows'
        }
        defaults['yara'] = {
            'filtered_yara': 'False',
            'dir_rules': 'yara-rules'
        }
        self.defaults = defaults

    def get(self, section, option):
        for conf in self.configs:
            try:
                return conf.get(section, option)
            except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
                continue
        return self.defaults[section][option]

    def options(self, section):
        options = set()
        for conf in self.configs:
            try:
                options.update(set(conf.options(section)))
            except ConfigParser.NoSectionError:
                pass
            finally:
                options.update(set(self.defaults[section].keys()))
        return options

    def has_option(self, section, option):
        has_option = False
        for conf in self.configs:
            has_option |= conf.has_option(section, option)
        return has_option or (option in self.defaults[section])

    def has_section(self, section):
        has_section = False
        for conf in self.configs:
            has_section |= conf.has_section(section)
        return has_section or (section in self.defaults)
