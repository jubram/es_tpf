# coding: utf-8

from es_tpf.models.plugin import Plugin
import re


class Parser(object):

    @staticmethod
    def nessus(plugin_df):

        matcher = re.compile('(Synopsis : )|( Description : )|( Solution : )|( Risk factor : )')
        plugin_df['Description'] = re.split(matcher, plugin_df['Description'])
        pid = "nessus-{}".format(plugin_df['Id'])

        if (plugin_df['Name'] == None) or (len(plugin_df) < 1):
            return False, 'Plugin name not defined.'
        else:
            p_mapped = Plugin.get_pid_df('mapped', pid)
            p_unmapped = Plugin.get_pid_df('unmapped', pid)
            if p_mapped is False and p_unmapped is False:
                title = plugin_df['Name']
                description = plugin_df['Description'][plugin_df['Description'].index(' Description : ') + 3] if ' Description : ' in plugin_df['Description'] else None
                rf = plugin_df['Risk Factor'].split(':')
                risk = rf[1].strip() if len(rf) > 1 else '0.0'
                categories = [plugin_df['Category'], plugin_df['Family']]
                cves = plugin_df['CVE Id(s)'].split(', ')
                references = {'ref': plugin_df['X-Reference(s)'].replace(' ', '').split(','),
                              'bugtraq': str(plugin_df['BugTraq Id(s)']).split(', ')}

                plugin = Plugin(title=title,
                           description=description,
                           type='nessus',
                           cvss=risk,
                           category=categories,
                           cve=cves,
                           cwe='',
                           refs=references,
                           dsk=[pid])

                return plugin.save('unmapped')
            else:
                return False, 'This plugin already exists on the database.'


    @staticmethod
    def qualys(plugin_df):

        pid = "qualys-{}".format(plugin_df['QID'])

        p_mapped = Plugin.get_pid_df('mapped', pid)
        p_unmapped = Plugin.get_pid_df('unmapped', pid)

        if (p_mapped is False) and (p_unmapped is False):
            plugin = Plugin(title=plugin_df['Title'],
                            description=None,
                            type='qualys',
                            cvss=plugin_df['CVSS Base'] if plugin_df['CVSS Base'] == '0' or plugin_df['CVSS Base'] == "'-" else plugin_df['CVSS Base'],
                            category=plugin_df['Sub Category'].split(', '),
                            cve=plugin_df['CVE ID'].split(','),
                            cwe='',
                            refs={'ref': plugin_df['Vendor Reference'].split(','), 'bugtraq': plugin_df['Bugtraq ID'].split(',')},
                            dsk=[pid])
            plugin.category.append(plugin_df['Category'])

            return plugin.save('unmapped')
        else:
            return False, 'This plugin already exists on the database.'