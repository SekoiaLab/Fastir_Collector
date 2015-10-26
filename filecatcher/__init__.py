from utils.utils import get_architecture
from ctypes import *
import os

arch = get_architecture()
fastir_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if arch == '64':
    try:
        msvcr = windll.msvcr120
        hdll = windll.checksignfromcat
    except:
        try:
            windll.LoadLibrary(os.path.join(fastir_dir, '_x64\\msvcr120.dll'))
            windll.LoadLibrary(os.path.join(fastir_dir, '_x64\\CheckSignFromCat.dll'))
        except:
            print "Failed load library 64 bits"
elif arch == '86':
    windll.LoadLibrary(os.path.join(fastir_dir, '_x86\\msvcr120.dll'))
    windll.LoadLibrary(os.path.join(fastir_dir, '_x86\\CheckSignFromCat.dll'))
else:
    print "Failed load library 32 bits"