import os

ALLOWED_EXTENSIONS = set(['csv'])
DATA_DIR = os.path.dirname(os.path.abspath(__file__)) + '/data'
DATABASE = 'es_tpf'
COLLECTIONS = ['mapped', 'unmapped', 'test_db']