import platform
import pkgutil
import os
import os.path
import sys

operating_sys = platform.system()

# Computing binary name
suffix = ""
if operating_sys == "Windows":
	if sys.maxsize > 2**32:
		suffix='_x64.exe'
	else:
		suffix= '_x86.exe'

binary_name = "FastIR" + suffix

# Finding dynamically loaded modules
sys.path.append(os.getcwd())
hidden_imports = []
additional_data = []
for module_loader, name, ispkg in pkgutil.walk_packages("."):
	if (len(sys.argv) == 2) or ((len(sys.argv) > 2) and (name.split(".")[0] in sys.argv)):
		if "." + operating_sys.lower() in name:
			hidden_imports.append(name)
		if ispkg:
			if '.' not in name:
				additional_data.append(name)

# Pyinstaller functions
a = Analysis(['main.py'], hiddenimports = hidden_imports, hookspath = ['hooks'])

pyz = PYZ(a.pure)

for pkg in additional_data:
	a.datas += Tree(pkg, prefix = pkg)

if os.path.isfile('FastIR.conf'):
    a.datas += [('FastIR.conf', 'FastIR.conf', 'DATA')]
else:
    a.datas += [('FastIR.conf', 'FastIR.conf.sample', 'DATA')]

exe = EXE(pyz, a.scripts, a.binaries, a.zipfiles, a.datas,
		  name = binary_name, debug = False, strip = None,
		  upx = True, console = True, icon="sekoia.ico")
