STARTSTR = {
    '%PDF-': 'application/pdf',

    'BZh': 'application/x-bzip2',
    'LRZI': 'application/x-lrzip',
    'LZIP': 'application/x-lzip',
    'PK': 'application/x-zip',
    '\037\235': 'application/x-compress',
    '\037\213': 'application/x-gzip',
    '\037\036': 'application/octet-stream',
    '\377\037': 'application/octet-stream',
    'MSCF\0\0\0\0': 'application/vnd.ms-cab-compressed',
    "7z\274\257'\042": 'application/x-7z-compressed',
    '\007**ACE**': 'application/x-ace',
    'Rar!': 'application/x-rar',
    '\334\247\304\375': 'application/x-zoo',
    '%TGIF': 'application/x-tgif',  # Qes aco?
    # '\320\317\021\340\241\261\032\341': 'application/x-ole-storage',
    '\320\317\021\340': 'application/x-ole-storage',

    'ustar\0': 'application/x-tar',
    'ustar  \0': 'application/x-tar',

    'P1': 'image/x-portable-bitmap',
    'P2': 'image/x-portable-greymap',
    'P3': 'image/x-portable-pixmap',
    'P4': 'image/x-portable-bitmap',
    'P5': 'image/x-portable-greymap',
    'P6': 'image/x-portable-pixmap',
    'IIN1': 'image/x-niff',
    'MM': 'image/tiff',
    'II': 'image/tiff',
    '/* XPM': 'image/x-xbm',
    'GIF8': 'image/gif',
    '\211PNG': 'image/png',
    'EP*\0': 'image/vnd.ms-modi',
    'GIF94z': 'image/unknown',
    'FGF95a': 'image/unknown',
    'PBF': 'image/unknown',
    # 'GIF':              'image/gif',
    'BM': 'image/bmp',
    '\377\330\377': 'image/jpeg',
    '\377\330': 'image/jpeg',
    'MM\0*': 'image/tiff',
    'II*\0': 'image/tiff',

    '\0\0\001\0\0': 'image/vnd.microsoft.icon',

    'FWS': 'application/vnd.adobe.flash.movie',
    'CWS': 'application/vnd.adobe.flash.movie',
    'idat': 'image/x-quicktime',

    'REGEDIT': 'text/x-ms-regedit',
    '$Windows Registry Editor Version 5.00': 'text/x-ms-regedit',
    '\377\376W\0i\0n\0d\0o\0w\0s\0 \0R\0e\0g\0i\0s\0t\0r\0y\0 \0E\0d\0i\0t\0o\0r\0': 'text/x-ms-regedit',

    '\012(': 'application/x-elc',
    ';ELC\023\000\000\000': 'application/x-elc',

    '%!': 'application/postscript',
    '\004%!': 'application/postscript',
    '\002%!': 'application/postscript',

    '\367\002': 'application/x-dvi',
    '\input texinfo': 'text/x-texinfo',
    'This is Info file': 'text/x-info',
    'documentclass': 'text/x-tex',
    '{\rtf': 'application/rtf',

    '\376\067\0\043': 'application/msword',
    '\333\245-\0\0\0': 'application/msword',

    '\224\246\056': 'application/msword',
    'PO^Q`': 'application/msword',
    'x\237>"': 'application/vnd.ms-tnef',

    '\320\317\021\340\241\261\032\341': 'application/msword',
    'WPC': 'application/vnd.wordperfect',
    '?_\003\0': 'application/winhlp',
    'PAR2': 'application/x-par2',
    '\231N\r\n': 'application/x-python-bytecode',  # ??
    '\003\363\r\n': 'application/x-python-bytecode',  # ??
    'mBIN': 'application/x-macbinary',
    #    'MZ':               'application/x-ms-dos-executable',
    'MSWIM\0\0\0': 'application/x-ms-wim',

    'PE\000\000': 'application/x-ms-pe',  # ??

    'OggS': 'video/ogg',

    '<!DOCTYPE HTML': 'text/html',
    '<!DOCTYPE html': 'text/html',
    '<HEAD': 'text/html',
    '<head': 'text/html',
    '<TITLE': 'text/html',
    '<title': 'text/html',
    '<html': 'text/html',
    '<HTML': 'text/html',
    '<!--': 'text/html',
    '<h1': 'text/html',
    '<H1': 'text/html',
}