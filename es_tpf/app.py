from es_tpf.config import DATABASE
from es_tpf.common.database import Database as db
from es_tpf.mapper import metrics

def run():
    db.initialize(DATABASE)
    metrics('nessus', 'qualys')