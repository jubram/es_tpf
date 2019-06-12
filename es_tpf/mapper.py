import csv
from es_tpf import config
from es_tpf.models.plugin import Plugin
from es_tpf.common.utils import Utils

def find_possible_matches(plugin_id):
    plugin = Plugin.get_by_pid('unmapped', plugin_id)
    all_unmapped = Plugin.get_all('unmapped')

    possible_matches = []
    i = 0

    for p in all_unmapped:
        if plugin_id == p.dsk[0]:
            continue
        r = plugin.update_similarity(p)
        if r > 0.8:
            possible_matches.append((p.dsk[0], r))
        Utils.progress(i, len(all_unmapped), ' Processing...')
        i += 1
    
    possible_matches.sort(reverse=True, key=lambda t: t[1])
    return possible_matches[:10]

def mapper():
    nessus = Plugin.get_by_scanner('unmapped', 'nessus')
    qualys = Plugin.get_by_scanner('unmapped', 'qualys')

    seen = []
    i = 1
    j = 0

    with open(f'{config.DATA_DIR}/results.csv', 'w') as csv_file:
        fieldnames = ['Plugin ID 1', 'Plugin Name 1', 'CVEs 1', 'Plugin ID 2', 'Plugin Name 2', 'CVEs 2', 'Similarity']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for p1 in nessus:
            print(f'Iteration #{i} of {len(nessus)} \n')
            i += 1
            matches = []
            seen.append(p1._id)
            for p2 in qualys:
                Utils.progress(j, len(qualys), 'Progress...')
                j += 1
                if p2._id in seen:
                    continue
                else:
                    m = p1.update_similarity(p2)
                    if not matches:
                        matches.append({'Plugin ID 1': p1.dsk[0]})
                        matches[0]['Plugin Name 1'] = p1.title
                        matches[0]['CVEs 1'] = ', '.join(p1.cve)
                        matches[0]['Plugin ID 2'] = p2.dsk[0]
                        matches[0]['Plugin Name 2'] = ', '.join(p2.title)
                        matches[0]['CVEs 2'] = p2.cve
                        matches[0]['Similarity'] = m
                    else:
                        if m > matches[0]['Similarity']:
                            matches = []
                            matches.append({'Plugin ID 1': p1.dsk[0]})
                            matches[0]['Plugin Name 1'] = p1.title
                            matches[0]['CVEs 1'] = ', '.join(p1.cve)
                            matches[0]['Plugin ID 2'] = p2.dsk[0]
                            matches[0]['Plugin Name 2'] = p2.title
                            matches[0]['CVEs 2'] = ', '.join(p2.cve)
                            matches[0]['Similarity'] = m
                        elif m == matches[-1]['Similarity']:
                            matches.append({'Plugin ID 1': p1.dsk[0]})
                            matches[-1]['Plugin Name 1'] = p1.title
                            matches[0]['CVEs 1'] = ', '.join(p1.cve)
                            matches[-1]['Plugin ID 2'] = p2.dsk[0]
                            matches[-1]['Plugin Name 2'] = p2.title
                            matches[0]['CVEs 2'] = ', '.join(p2.cve)
                            matches[-1]['Similarity'] = m
            for match in matches:
                writer.writerow(match)
            j = 0

if __name__ == '__main__':
    mapper()