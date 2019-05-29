from es_tpf.config import DATABASE
from es_tpf.common.database import Database as db
from es_tpf.metrics import metrics
from es_tpf import mapper

def run():
    db.initialize(DATABASE)
    possible_matches = mapper.find_possible_matches('nessus-10026')
    print(possible_matches)