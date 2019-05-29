from es_tpf import config
from es_tpf.common.utils import Utils
from es_tpf.common.database import Database as db
from es_tpf.models.plugin import Plugin

def known_matches(mapping, plugins, tool):
    print('\n=+=+= Starting Known Matches =+=+=\n')
    input('Press any key to continue\n> ')

    true_positives = 0
    false_positives = 0

    for i in range(len(mapping)):

        p1 = Plugin.get_by_pid(config.COLLECTIONS[2], f'{tool}-{mapping.NID[i]}')
        if not p1:
            print(f'Nessus ID not found: {mapping.NID[i]}')
            input('Type anything to continue...')
        else:
            for p2 in plugins:
                p2_id = p2.dsk[0].split('-')[1]
                r = p1.update_similarity(p2)
                if p2_id == str(mapping.QID[i]):
                    if r > 0.65:
                        true_positives += 1
                    else:
                        false_positives += 1
        Utils.progress(i, len(mapping), ' Processing...')
    print('\n=+=+= Done! =+=+=\n')
    return true_positives, false_positives

def not_matches(unique, plugins, tool):
    print(f'\n=+=+= Starting Unique {tool.title()} =+=+=\n')
    input('Press any key to continue\n> ')
    
    false_negatives = 0
    true_negatives = 0
    i = 0

    for p1 in unique:
        fail = False
        for p2 in plugins:
            r = p1.update_similarity(p2)
            # Utils.print_progress(n=n, q=p, similarity=r)
            if r > 0.55:
                fail = True
        Utils.progress(i, len(unique))
        if fail:
            false_negatives += 1
        else:
            true_negatives += 1
        i += 1
    print('\n=+=+= Done! =+=+=\n')
    return false_negatives, true_negatives

def metrics(tool1, tool2, verbose=0):
    #db.initialize(DATABASE)

    # === All plugins separated by scanner === #

    all1 = Plugin.get_by_scanner(config.COLLECTIONS[2], tool1)
    len_all1 = len(all1)
    all2 = Plugin.get_by_scanner(config.COLLECTIONS[2], tool2)
    len_all2 = len(all2)

    # =+=+= END =+=+= #

    # === Known unique plugins separated by scanner === #

    not_matching = Utils.open_csv(f'{config.DATA_DIR}/{config.UNMATCHING_FILE}')
    unique1 = []
    unique2 = []

    for n, q in zip(not_matching.NID, not_matching.QID):
        unique1.append(Plugin.get_by_pid(config.COLLECTIONS[2], f'{tool1}-{n}'))
        unique2.append(Plugin.get_by_pid(config.COLLECTIONS[2], f'{tool2}-{q}'))

    len_unique1 = len(unique1)
    len_unique2 = len(unique2)

    # =+=+= END =+=+= #


    # === Known matches === #

    mapping = Utils.open_csv(f'{config.DATA_DIR}/{config.MATCHING_FILE}')

    # =+=+= END =+=+= #


    # === Start === #

    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0

    # Check the known matches

    tp, fp = known_matches(mapping, all2, tool1)
    true_positives += tp
    false_positives += fp

    fn, tn = not_matches(unique1, all2, tool1)
    false_negatives += fn
    true_negatives += tn

    fn, tn = not_matches(unique2, all1, tool2)
    false_negatives += fn
    true_negatives += tn

    # Print the results
    Utils.print_results(true_positives, false_positives, false_negatives, true_negatives)

if __name__ == '__main__':
    metrics()