from es_tpf.config import DATABASE
from es_tpf.common.database import Database as db
from es_tpf.metrics import metrics
from es_tpf import mapper

def run():
    db.initialize(DATABASE)
    