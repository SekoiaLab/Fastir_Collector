from zipfile import ZipFile


class _Archives(ZipFile):
    def __init__(self, path_archive, logger):
        self.logger = logger
        self.logger.info("Archive creating: %s " % path_archive)
        super(_Archives, self).__init__(path_archive, 'a', allowZip64=True)
        self.logger.info("Archive created: %s " % path_archive)

    def __del__(self):
        self.close()
        super(_Archives, self).__del__()

    def record(self, path):
        try:
            path_zip_format = path.replace("\\", "/")
            path_zip_format = path_zip_format.replace("//?/GLOBALROOT/", "")
            if path_zip_format not in self.namelist():
                self.write(path)
        except Exception as e:
            self.logger.error(str(e))
