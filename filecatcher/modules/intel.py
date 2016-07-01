from base_modules import _Base_Modules
import os
import yara
import glob


class _Intel(_Base_Modules):
    def __init__(self, path, params):
        super(_Intel, self).__init__(path, params)
        self.dir_rules = self.params['dir_rules']
        self.rules = self._load_yara_rules()

    def process(self):
        rules = self._is_match()
        if rules and len(rules) > 0:
            return '|'.join([str(r) for r in rules])
        else:
            return None

    def _load_yara_rules(self):
        namespaces = dict([(os.path.basename(n), n) for n in glob.glob(os.path.join(os.path.abspath(self.dir_rules), '*.yar')) if os.path.isdir(self.dir_rules)])
        if namespaces:
            return yara.compile(filepaths=namespaces)
        return {}

    def _is_match(self):
        try:
            with open(self.path, 'rb') as f:
                if self.rules:
                    matches = self.rules.match(data=f.read())
                    return matches
                else:
                    return []
        except IOError as e:
            self.params['logger'].error(str(e))
            return []
