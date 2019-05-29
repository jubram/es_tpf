from utils import Utils
from config import DATA_DIR, DATABASE, COLLECTIONS
from plugin import Plugin
from database import Database as db

def known_matches(mapping, plugins, tool):
    print('\n=+=+= Starting Known Matches =+=+=\n')
    input('Press any key to continue\n> ')

    true_positives = 0
    false_positives = 0

    for i in range(len(mapping)):

        p1 = Plugin.get_by_pid(COLLECTIONS[2], f'{tool}-{mapping.NID[i]}')
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

def metrics(verbose=0):
    db.initialize(DATABASE)

    # === All plugins separated by scanner === #

    all_nessus = Plugin.get_by_scanner(COLLECTIONS[2], 'nessus')
    len_all_nessus = len(all_nessus)
    all_qualys = Plugin.get_by_scanner(COLLECTIONS[2], 'qualys')
    len_all_qualys = len(all_qualys)

    # =+=+= END =+=+= #

    predicted = {}

    # === Known unique plugins separated by scanner === #

    not_matching = Utils.open_csv('{}/not_match.csv'.format(DATA_DIR))
    unique_nessus = []
    unique_qualys = []

    for n, q in zip(not_matching.NID, not_matching.QID):
        unique_nessus.append(Plugin.get_by_pid(COLLECTIONS[2], 'nessus-{}'.format(n)))
        unique_qualys.append(Plugin.get_by_pid(COLLECTIONS[2], 'qualys-{}'.format(q)))

    len_unique_nessus = len(unique_nessus)
    len_unique_qualys = len(unique_qualys)

    # =+=+= END =+=+= #


    # === Known matches === #

    mapping = Utils.open_csv('{}/matches.csv'.format(DATA_DIR))

    # =+=+= END =+=+= #


    # === Start === #

    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0

    # Check the known matches

    tp, fp = known_matches(mapping, all_qualys, 'nessus')
    true_positives += tp
    false_positives += fp

    fn, tn = not_matches(unique_nessus, all_qualys, 'nessus')
    false_negatives += fn
    true_negatives += tn

    fn, tn = not_matches(unique_qualys, all_nessus, 'qualys')
    false_negatives += fn
    true_negatives += tn

    # Print the results
    Utils.print_results(true_positives, false_positives, false_negatives, true_negatives)

if __name__ == '__main__':
    metrics()