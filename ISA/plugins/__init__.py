from glob import glob
from keyword import iskeyword
from os.path import dirname, join, split, splitext
import sys

basedir = dirname(__file__)

__all__ = []
for name in glob(join(basedir, '*.py')):
    module = splitext(split(name)[-1])[0]
    if not module.startswith('_') and not iskeyword(module):
        try:
            __import__(__name__+'.'+module)
        except:
            e = sys.exc_info()
            print e
        else:
            __all__.append(module)
__all__.sort()
