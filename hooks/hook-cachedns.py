import sys

if sys.maxsize > 2 ** 32:

    datas = [("./../_x64/boost_python-vc120-gd-1_55.dll", ''),
             ("./../_x64/boost_python-vc120-gd-1_55.lib", ''),
             ("./../_x64/boost_python-vc120-mt-gd-1_55.lib", ''),
             ("./../_x64/msvcp120d.dll", ''),
             ("./../_x64/msvcr120d.dll", ''),
             ("./../memory/dnscache_x64.pyd"),
    ]

else:

    datas = [("./../_x86/boost_python-vc120-gd-1_55.dll", ''),
             ("./../_x86/boost_python-vc120-gd-1_55.lib", ''),
             ("./../_x86/boost_python-vc120-mt-gd-1_55.lib", ''),
             ("./../_x86/msvcp120d.dll", ''),
             ("./../_x86/msvcr120d.dll", ''),
             ("./../memory/dnscache_x64.pyd", ''),
    ]