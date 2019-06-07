from es_tpf.config import DATABASE
from es_tpf.common.database import Database as db
from es_tpf.common.utils import Utils
from es_tpf.metrics import metrics
from es_tpf import mapper

def run():
    db.initialize(DATABASE)
    collections = db.get_collections()
    if len(collections) == 0:
        Utils.build_db(verbose=True)
        Utils.build_test_db()
    
    metrics('nessus', 'qualys')