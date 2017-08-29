# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import argparse
import ctypes
import glob
import inspect
import logging
import multiprocessing
import os
import platform
import random
import re
import string
import sys
import traceback
from datetime import datetime

import wmi
import yaml

import factory.factory as factory
import settings
from settings import EXTRACT_DUMP, USERS_FOLDER
from utils.conf import CustomConf
from utils.utils import change_char_set_os_environ, get_os_version, mount_share, unmount_share, look_for_files, \
                        zip_archive, delete_dir
from utils.vss import _VSS


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

    # initiating the stream handler
    fs = InfoStreamHandler(sys.stdout)
    fs.setFormatter(log_format)
    logger.addHandler(fs)
    param_options["logger"] = logger


def detect_os():
    c = wmi.WMI()
    version = []
    for c in c.Win32_OperatingSystem():
        version.append(c.Name)
    # name_version = version[0]


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

    if "homedrive" in param_options:
        param_options["USERPROFILE"] = param_options["homedrive"] + os.path.splitdrive(param_options["USERPROFILE"])[1]

    if "fs" in param_options:
        user_env_var = ["TEMP", "USERPROFILE", "APPDATA", "LOCALAPPDADATA", "TMP"]
        fs = set()
        for entry in param_options["fs"].split(","):
            d = entry.split('|')[0]
            depth = entry.split('|')[1]
            env_var = replace_env(d)
            if env_var:
                if env_var in user_env_var:
                    if param_options["all_users"]:
                        path = d.replace("%" + env_var + "%", os.environ[env_var])
                        path = path.replace(username, "*")

                        for p in glob.glob(path):
                            fs.add(p + '|' + depth)
                    else:
                        try:
                            fs.add(d.replace("%" + d[1:len(d) - 1] + "%", os.environ[d[1:len(d) - 1]]) + '|' + depth)
                        except KeyError:
                            sys.stderr.write("Environment variable '%s' doesn't exist\n" % d)
                else:
                    try:
                        fs.add(d.replace("%" + env_var + "%", os.environ[env_var]) + '|' + depth)
                    except KeyError:
                        sys.stderr.write("Environment variable '%s' doesn't exist\n" % d)
            elif os.path.isdir(d):
                fs.add(d + '|' + depth)
            else:
                sys.stderr.write("Could not find directory '%s'\n" % d)
        param_options["fs"] = fs
        if param_options["zip"] == "True":
            param_options["zip"] = True
        else:
            param_options["zip"] = False
    return param_options


def profile_used(paths, param_options):
    config = CustomConf(paths)

    param_options["packages"] = [p.lower() for p in config.get("profiles", "packages").split(",")]

    param_options["output_type"] = config.get("output", "type")
    param_options["output_dir"] = config.get("output", "dir")
    param_options["output_excel"] = yaml.safe_load(config.get("output", "excel"))
    if config.has_option("output", "share"):
        param_options["output_share"] = config.get("output", "share")

    if config.has_option("output", "share_dir"):
        param_options["share_dir"] = config.get("output", "share_dir")
    else:
        param_options["share_dir"] = None

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
        param_options["all_users"] = yaml.safe_load(config.get("filecatcher", "all_users"))
        param_options['compare'] = config.get('filecatcher', 'compare')
        param_options['limit_days'] = config.get('filecatcher', 'limit_days')

    if config.has_section("dump"):
        param_options["dump"] = config.get("dump", "dump")
        if config.has_option('dump', 'mft_export'):
            param_options["mft_export"] = yaml.safe_load(config.get("dump", "mft_export"))
        else:
            param_options["mft_export"] = True

    if config.has_section("registry"):
        if config.has_option("registry", "custom_registry_keys"):
            param_options["custom_registry_keys"] = config.get("registry", "custom_registry_keys")
            param_options["registry_recursive"] = yaml.safe_load(config.get("registry", "registry_recursive"))
        if config.has_option('registry', 'get_autoruns'):
            param_options["get_autoruns"] = yaml.safe_load(config.get('registry', "get_autoruns"))
        else:
            param_options["get_autoruns"] = False
    else:
        param_options['get_autoruns'] = False

    if config.has_section('modules'):
        for mod in config.options('modules'):
            for module_option in config.options(mod):
                param_options[module_option] = config.get(mod, module_option)
    if config.has_section('extension'):
        if config.has_option('extension', 'random'):
            if yaml.safe_load(config.get("extension", "random")):
                param_options["rand_ext"] = "." + "".join(
                    [random.SystemRandom().choice(string.ascii_lowercase) for _ in xrange(5)])
            else:
                param_options["rand_ext"] = "." + param_options["output_type"]
        else:
            param_options["rand_ext"] = "." + param_options["output_type"]
    else:
        param_options["rand_ext"] = "." + param_options["output_type"]

    if config.has_section('env'):
        for option in config.options('env'):
            param_options[option] = config.get('env', option)
    return param_options


def create_dir(dir_create):
    """Creates directory"""
    try:
        os.makedirs(dir_create)
    except OSError:
        pass


def create_output_dir(output_dir):
    """Creates 'output_dir' recursively"""
    env_var = replace_env(output_dir)
    if env_var:
        try:
            output_dir = output_dir.replace("%" + env_var + "%", os.environ[env_var])
        except KeyError:
            sys.stderr.write("Environment variable '%s' doesn't exist\n" % env_var)
            sys.stderr.write("'%s' doesn't exist\n" % output_dir)
            sys.exit(1)

    output_dir = output_dir + os.path.sep + datetime.now().strftime("%Y-%m-%d_%H%M%S") + os.path.sep
    create_dir(output_dir)

    return output_dir


def replace_env(env_string):
    reg_env = re.compile("%([^%]*)%")
    result = reg_env.match(env_string)
    if result:
        result = result.group(1)
    return result


def create_share_dir(output_share, share_dir):
    if share_dir:
        share_dir = os.path.join(output_share, share_dir, datetime.now().strftime("%Y-%m-%d_%H%M%S"))
    else:
        share_dir = os.path.join(output_share, datetime.now().strftime("%Y-%m-%d_%H%M%S"))

        create_dir(share_dir)
    return share_dir


def parse_command_line():
    """Parse command line arguments and return them in a way that python can use directly"""

    parser = argparse.ArgumentParser(description="FastIR")

    parser.add_argument("--packages", dest="packages",
                        help=("List of packages all,memory,registry,evt,fs,health. And advanced packages: filecatcher,"
                              "dump \r\n use: --packages all or --packages fs,memory"))
    parser.add_argument("--output_dir", dest="output_dir", help="Output directory path")
    parser.add_argument("--output_type", dest="output_type", help="Specify output format (json or csv)")
    parser.add_argument("--excel", dest="output_excel", action="store_true", help="When enabled will limit csv fields size at ~30k chars")
    parser.add_argument("--dump", dest="dump",
                        help="use: --dump ram if you want to dump ram. To list dump functionalities, --dump list")
    parser.add_argument("--profile", dest="profile", help="--profile path\\to\\yourprofile.conf")
    parser.add_argument("--homedrive", dest="homedrive", help="--homedrive drive: to manually set HOMEDRIVE for FastIR")
    args = parser.parse_args()

    if args.dump == "list":
        print ",".join(EXTRACT_DUMP.keys())
        sys.exit(0)

    return args, parser


def parse_config_file(config_file, param_options):
    """Verify that if a conf file is given as a parameter it exists, and checks
    if the app is frozen (i.e. "compiled") or  not, to include the right path."""

    config_files = list()

    if config_file:
        # If a config_file was specified but doesn't exist, tell the user and quit rather than using default conf
        if not os.path.isfile(config_file):
            sys.stderr.write("Error: config file '%s' not found" % config_file)
            sys.exit(1)
        else:
            config_files.append(config_file)

    # If app is frozen with pyinstaller, look for temporary file path
    if hasattr(sys, "frozen"):
        config_files.append(os.path.join(sys._MEIPASS, 'FastIR.conf'))
    else:
        # if running from sources, use the conf file in the current directory
        config_files.append("FastIR.conf")

    return profile_used(config_files, param_options)


def set_command_line_options(param_options, args):
    """Override 'options' with command line options specified in 'args'"""
    for option in vars(args):
        if getattr(args, option):
            if option in ["packages"]:
                param_options[option] = [p.lower() for p in list(set(getattr(args, option).split(",")))]
            else:
                param_options[option] = getattr(args, option)

    if args.output_type is not None and param_options['rand_ext'] in ('.json', '.csv'):
        param_options['rand_ext'] = '.' + args.output_type

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

    if "homedrive" in param_options:
        if not re.match('^[A-z]:$', param_options["homedrive"]):
            parser.print_help()
            sys.stderr.write("\nhomedrive expected to be in '[A-z]:' format.")
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

    # if share is specified, also created remote directory
    try:
        if param_options["destination"] == "share":
            mount_letter = mount_share(param_options["output_share"],
                                       param_options["share_login"],
                                       param_options["share_password"])
            param_options["mount_letter"] = mount_letter
            if mount_letter:
                create_share_dir(mount_letter, param_options["output_dir"])
            else:
                create_share_dir(param_options["output_share"], param_options["output_dir"])
        else:
            param_options["output_dir"] = create_output_dir(os.path.join(os.path.dirname(__file__),
                                                                         param_options["output_dir"]))
    except Exception:
            param_options["output_dir"] = create_output_dir(os.path.join(os.path.dirname(__file__),
                                                                         param_options["output_dir"]))
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

    if param_options["destination"] == "share":
        report_files = look_for_files(param_options["output_dir"])
        zip_archive(report_files, param_options["output_share"], "fastIR_report", param_options["logger"])
        delete_dir(param_options["output_dir"])
        if "mount_letter" not in param_options:
            unmount_share(param_options["output_share"])

    param_options['logger'].info('Check here %s for yours results' % os.path.abspath(param_options['output_dir']))


if __name__ == "__main__":
    # Add multiprocessing support when frozen with pyinstaller
    if hasattr(sys, "frozen"):
        multiprocessing.freeze_support()

    options = set_options()
    sys.exit(main(options))
