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
        if r > 0.65:
            possible_matches.append((p.dsk[0], r))
        Utils.progress(i, len(all_unmapped), ' Processing...')
        i += 1
    
    possible_matches.sort(reverse=True, key=lambda t: t[1])
    return possible_matches[:10]