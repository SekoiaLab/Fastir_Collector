from ConfigParser import ConfigParser

class _Base_Modules(object):
    def __init__(self, path, params):
        self.path = path
        self.params = params

    def process(self):
        raise NotImplementedError("You must implement a process method")
