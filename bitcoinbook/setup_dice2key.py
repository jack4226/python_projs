from distutils.core import setup
import py2exe, sys, os

# for py2exe
sys.argv.append('py2exe')

setup(
    options = {'py2exe':
        {'optimize': 2, 
         'bundle_files': 1,
         'compressed': True,
         },
    },
    console = ['dice2key.py'],
    zipfile = None,    
    version="0.1.0",
    description="Dice2Key Address Generator",
    author="deepceleron",
    )