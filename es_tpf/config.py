import os

ALLOWED_EXTENSIONS = set(['csv'])
DATABASE = 'es_tpf'
COLLECTIONS = ['mapped', 'unmapped', 'test_db']

DATA_DIR = os.path.dirname(os.path.abspath(__file__)) + '/resources'
MATCHING_FILE = 'matches.csv'
UNMATCHING_FILE = 'not_match.csv'