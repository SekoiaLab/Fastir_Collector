# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import ConfigParser
import argparse
from datetime import datetime
import glob
import inspect
import logging
import multiprocessing
import os
import platform
import re
import sys
import traceback
import yaml
from utils.utils import mount_share, unmount_share, get_os_version, change_char_set_os_environ
from utils.vss import _VSS
import wmi
import factory.factory as factory
from settings import USERS_FOLDER, EXTRACT_DUMP
import ctypes
import settings
import random
import string


def set_logger(param_options):
    # Stream logger class for printing only INFO level messages
    class InfoStreamHandler(logging.StreamHandler):
        def __init__(self, stream):
            logging.StreamHandler.__init__(self, stream)

        def emit(self, record):
            if not record.levelno == logging.INFO:
                return
            logging.StreamHandler.emit(self, record)

    # initiating the logger and the string format
    logger = logging.getLogger("FastIR")
    logger.setLevel(logging.INFO)
    create_dir(param_options["output_dir"])
    log_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # initiating the filehandler
    fh = logging.FileHandler(os.path.join(param_options["output_dir"], "FastIR.log"), encoding="UTF-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(log_format)
    logger.addHandler(fh)

    # initiatinig the stream handler
    fs = InfoStreamHandler(sys.stdout)
    fs.setFormatter(log_format)
    logger.addHandler(fs)
    param_options["logger"] = logger


def detect_os():
    c = wmi.WMI()
    version = []
    for c in c.Win32_OperatingSystem():
        version.append(c.Name)
    name_version = version[0]


def set_environment_options(param_options):
    os.environ = change_char_set_os_environ(os.environ)
    operating_sys = platform.system()

    if operating_sys == settings.OS:
        release = get_os_version()

    else:
        sys.stderr.write("OS not supported\n")
        sys.exit(1)

    param_options["system_root"] = os.environ["SYSTEMROOT"]
    param_options["computer_name"] = os.environ["COMPUTERNAME"]
    param_options["USERPROFILE"] = USERS_FOLDER[operating_sys + release]
    param_options["OS"] = operating_sys
    param_options["release"] = release

    try:
        username = os.environ["USERNAME"]
    except KeyError:
        username = os.environ["USERPROFILE"].split("\\")[-1]

    if "fs" in param_options:
        user_env_var = ["TEMP", "USERPROFILE", "APPDATA", "LOCALAPPDADATA", "TMP"]
        fs = []
        for entry in param_options["fs"].split(","):
            d = entry.split('|')[0]
            depth = entry.split('|')[1]
            reg_env = re.compile("%([^%]*)%")
            result = reg_env.match(d)
            if result:
                env_var = result.group(1)
                if env_var in user_env_var:
                    if param_options["all_users"]:
                        path = d.replace("%" + env_var + "%", os.environ[env_var])
                        path = path.replace(username, "*")

                        for p in glob.glob(path):
                            fs.append(p + '|' + depth)
                    else:
                        try:
                            fs.append(d.replace("%" + d[1:len(d) - 1] + "%", os.environ[d[1:len(d) - 1]]) + '|' + depth)
                        except KeyError:
                            sys.stderr.write("Environment variable '%s' doesn't exist\n" % d)
                else:
                    try:
                        fs.append(d.replace("%" + env_var + "%", os.environ[env_var]) + '|' + depth)
                    except KeyError:
                        sys.stderr.write("Environment variable '%s' doesn't exist\n" % d)
            elif os.path.isdir(d):
                fs.append(d + '|' + depth)
            else:
                sys.stderr.write("Could not find directory '%s'\n" % d)
        param_options["fs"] = fs
        if param_options["zip"] == "True":
            param_options["zip"] = True
        else:
            param_options["zip"] = False

    return param_options


def profile_used(path, param_options):
    file_conf = path
    config = ConfigParser.ConfigParser(allow_no_value=True)
    config.readfp(open(file_conf))
    param_options["packages"] = [p.lower() for p in config.get("profiles", "packages").split(",")]

    param_options["output_type"] = config.get("output", "type")
    param_options["output_destination"] = config.get("output", "destination")
    param_options["output_dir"] = config.get("output", "dir")
    if config.has_option("output", "share"):
        param_options["output_share"] = config.get("output", "share")

    if config.has_option("output", "share_login"):
        param_options["share_login"] = config.get("output", "share_login")
    else:
        param_options["share_login"] = None

    if config.has_option("output", "share_password"):
        param_options["share_password"] = config.get("output", "share_password")
    else:
        param_options["share_password"] = None
    if config.has_option('output', 'destination'):
        param_options['destination'] = config.get('output', 'destination')
    else:
        param_options['destination'] = 'local'
    if config.has_section("filecatcher"):
        param_options["size_min"] = config.get("filecatcher", "size_min")
        param_options["size_max"] = config.get("filecatcher", "size_max")
        param_options["fs"] = config.get("filecatcher", "path")
        param_options["mime_filter"] = config.get("filecatcher", "mime_filter")
        param_options["mime_zip"] = config.get("filecatcher", "mime_zip")
        param_options["zip"] = config.get("filecatcher", "zip")
        param_options["ext_file"] = config.get("filecatcher", "ext_file")
        param_options["zip_ext_file"] = config.get("filecatcher", "zip_ext_file")
        param_options["all_users"] = yaml.load(config.get("filecatcher", "all_users"))
        param_options['compare'] = config.get('filecatcher', 'compare')
        param_options['limit_days'] = config.get('filecatcher', 'limit_days')

    if config.has_section("dump"):
        param_options["dump"] = config.get("dump", "dump")
        if config.has_option('dump', 'mft_export'):
            param_options["mft_export"] = config.get("dump", "mft_export")
        else:
            param_options["mft_export"] = True

    if config.has_section("registry"):
        if config.has_option("registry","custom_registry_keys"):
            param_options["custom_registry_keys"] = config.get("registry", "custom_registry_keys")
            param_options["registry_recursive"] = yaml.load(config.get("registry", "registry_recursive"))
        if config.has_option('registry','get_autoruns'):
            param_options["get_autoruns"] = yaml.load(config.get('registry', "get_autoruns"))
        else:
            param_options["get_autoruns"] = False
    else:
        param_options['get_autoruns'] = False

    if config.has_section('modules'):
        for module in config.options('modules'):
            for module_option in config.options(module):
                param_options[module_option] = config.get(module, module_option)
    if config.has_section('extension'):
        if config.has_option('extension', 'random'):
            if yaml.load(config.get("extension","random")):
                param_options["rand_ext"] = "." + "".join(
                    [random.SystemRandom().choice(string.ascii_lowercase) for _ in xrange(5)])
            else:
                param_options["rand_ext"] = '.csv'
        else:
            param_options["rand_ext"] = '.csv'
    else:
        param_options["rand_ext"] = '.csv'

    if config.has_section('env'):
        for option in config.options('env'):
            params[option] = config.get('env',option)
    return param_options


def create_dir(dir_create):
    """Creates directory"""
    try:
        os.makedirs(dir_create)
    except OSError:
        pass


def create_output_dir(output_dir, letter=None):
    """Creates 'output_dir' recursively"""
    reg_env = re.compile("%([^%]*)%")
    result = reg_env.match(output_dir)
    if result:
        env_var = result.group(1)
        try:
            output_dir = output_dir.replace("%" + env_var + "%", os.environ[env_var])
        except KeyError:
            sys.stderr.write("Environment variable '%s' doesn't exist\n" % env_var)
            sys.stderr.write("'%s' doesn't exist\n" % output_dir)
            unmount_share(letter)
            sys.exit(1)

    if letter:
        output_dir = letter + os.path.sep + output_dir + os.path.sep + datetime.now().strftime(
                "%Y-%m-%d_%H%M%S") + os.path.sep
    else:
        output_dir = output_dir + os.path.sep + datetime.now().strftime("%Y-%m-%d_%H%M%S") + os.path.sep
    create_dir(output_dir)

    return output_dir


def parse_command_line():
    """Parse command line arguments and return them in a way that python can use directly"""

    parser = argparse.ArgumentParser(description="FastIR")

    parser.add_argument("--packages", dest="packages",
                        help=("List of packages all,memory,registry,evt,fs,health. And advanced packages: filecatcher,"
                              "dump \r\n use: --packages all or --packages fs,memory"))
    parser.add_argument("--output_dir", dest="output_dir", help="Directory path for CSV outputs")
    parser.add_argument("--dump", dest="dump",
                        help="use: --dump ram if you want to dump ram. To list dump functionalities, --dump list")

    parser.add_argument("--profile", dest="profile", help="--profile yourfile.conf. The filepath must be absolute")

    args = parser.parse_args()

    if args.dump == "list":
        print ",".join(EXTRACT_DUMP.keys())
        sys.exit(0)

    return args, parser


def parse_config_file(config_file, param_options):
    """Parse config file specified in argument, or default config file (FastIR.conf)"""
    # If no config_file was specified, fallback to bundled config
    if not config_file:
        config_file = "FastIR.conf"
        # If app is frozen with pyinstaller, look for temporary file path
        if hasattr(sys, "frozen"):
            config_file = os.path.join(sys._MEIPASS, config_file)
    else:
        # If a config_file was specified but doesn"t exist, tell the user and quit
        if not os.path.isfile(config_file):
            sys.stderr.write("Error: config file '%s' not found" % config_file)
            sys.exit(1)

    if os.path.isfile(config_file):
        return profile_used(config_file, param_options)
    else:
        return {}


def set_command_line_options(param_options, args):
    """Override 'options' with command line options specified in 'args'"""
    for option in vars(args):
        if getattr(args, option):
            if option in ["packages"]:
                param_options[option] = [p.lower() for p in list(set(getattr(args, option).split(",")))]
            else:
                param_options[option] = getattr(args, option)

    return param_options


def validate_options(param_options, parser):
    """Validate that 'options' are valid. If not, print usage and quit"""
    for option in ["output_dir", "packages", "output_type"]:
        if option not in param_options:
            parser.print_help()
            sys.stderr.write("\nMissing required option: %s\n" % option)
            sys.exit(1)

    if "dump" in param_options["packages"]:
        if "dump" not in param_options:
            parser.print_help()
            sys.stderr.write("\nMissing dump list\n")
            sys.exit(1)

    if "fs" in param_options:
        if "size" not in param_options and "mime_filter" not in param_options:
            parser.print_help()
            sys.stderr.write("\nMissing fs filters ('size' and/or 'mime_filter')")
            sys.exit(1)


def set_options():
    """Define all options needed for execution, based on config, command line and environment"""
    # First, parse command line arguments
    args, parser = parse_command_line()
    param_options = {}

    # Parse the config file to load default options
    param_options = parse_config_file(args.profile, param_options)

    # Override with command line options, if any
    param_options = set_command_line_options(param_options, args)

    # Check if options are valid
    validate_options(param_options, parser)

    # Set options based on environment
    param_options = set_environment_options(param_options)

    # if share and output are both specified, create output folder in share
    try:
        if "output_share" in param_options:
            mount_letter = mount_share(param_options["output_share"],
                                       param_options["share_login"],
                                       param_options["share_password"])
            param_options["output_dir"] = create_output_dir(param_options["output_dir"], mount_letter)
            param_options["mount_letter"] = mount_letter
        else:
            param_options["output_dir"] = create_output_dir(os.path.join(os.path.dirname(__file__),param_options["output_dir"]))
    except Exception as e:
            param_options["output_dir"] = create_output_dir(os.path.join(os.path.dirname(__file__),param_options["output_dir"]))
    return param_options


def main(param_options):
    print r"""
  ______        _   _____ _____
 |  ____|      | | |_   _|  __ \
 | |__ __ _ ___| |_  | | | |__) |
 |  __/ _` / __| __| | | |  _  /
 | | | (_| \__ \ |_ _| |_| | \ \
 |_|  \__,_|___/\__|_____|_|  \_\

     A forensic analysis tool
    """
    import time
    time.sleep(2)

    # check administrative rights
    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        print "ERROR: FastIR Collector must run with administrative privileges\nPress ENTER to finish..."
        sys.stdin.readline()
        return 0

    set_logger(param_options)

    modules = factory.load_modules(param_options["packages"], param_options["output_dir"])

    for m in modules:
        classes = factory.load_classes(m, param_options["OS"], param_options["release"])
        for cl in classes:
            instance = cl(param_options)
            if "dump" in str(cl):
                for opt in param_options["dump"].split(","):
                    try:
                        if opt in EXTRACT_DUMP:
                            list_method = EXTRACT_DUMP[opt]

                            for method in list_method:
                                if method.startswith(param_options["output_type"]):
                                    getattr(instance, method)()
                    except Exception:
                        param_options["logger"].error(traceback.format_exc())
                continue
            for name, method in inspect.getmembers(cl, predicate=inspect.ismethod):
                if not name.startswith("_"):
                    try:
                        if param_options["output_type"] in name:
                            getattr(instance, name)()
                    except KeyboardInterrupt:
                        return 0
                    except Exception:
                        param_options["logger"].error(traceback.format_exc())

    # Delete all shadow copies created during the acquisition process
    _VSS._close_instances()

    if "mount_letter" in param_options:
        unmount_share(param_options["mount_letter"])

    param_options['logger'].info('Check here %s for yours results' % os.path.abspath(param_options['output_dir']))
if __name__ == "__main__":
    # Add multiprocessing support when frozen with pyinstaller
    if hasattr(sys, "frozen"):
        multiprocessing.freeze_support()

    options = set_options()
    sys.exit(main(options))
