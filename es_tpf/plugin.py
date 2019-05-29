# -*- coding: utf-8 -*-

import uuid
import operator

from nltk import RegexpTokenizer
from nltk.corpus import stopwords
from fuzzywuzzy import fuzz
import re

import pandas as pd

from database import Database as db


class Plugin(object):

    def __init__(self, title, description, cvss, type, refs={}, dsk=[], cve=[], cwe=[], category=[], similarity={}, collection='plugins', _id=None):

        self.title = title
        self.description = description
        self.cvss = cvss
        self.category = category
        self.type = type
        self.refs = refs
        self.dsk = dsk
        self.cve = cve
        self.cwe = cwe
        self.similarity = similarity
        self._id = uuid.uuid4().hex if _id is None else _id
        self.matches = []

    def save(self, collection):
        return db.update(collection, {'_id': self._id}, self.jsonify())

    @classmethod
    def get_by_title(cls, collection, title):
        try:
            return cls(**db.find_one(collection, {'title': title}))
        except TypeError:
            return False

    @staticmethod
    def get_title_df(collection, title):
        r = db.find_one(collection, {'title': title})
        if not r:
            return False
        else:
            p = pd.DataFrame.from_dict(r, orient='index')
            return p.transpose()

    @classmethod
    def get_by_id(cls, collection, _id):
        try:
            return cls(**db.find_one(collection, {'_id': _id}))
        except TypeError:
            return False

    @classmethod
    def get_by_pid(cls, collection, pid):
        try:
            return cls(**db.find_one(collection, {'dsk': pid}))
        except TypeError:
            return False

    @staticmethod
    def get_id_df(collection, _id):
        r = db.find_one(collection, {'_id': _id})
        if not r:
            return False
        else:
            p = pd.DataFrame.from_dict(r, orient='index')
            return p.transpose()

    @staticmethod
    def get_pid_df(collection, pid):
        r = db.find_one(collection, {'dsk': pid})
        if not r:
            return False
        else:
            p = pd.DataFrame.from_dict(r, orient='index')
            return p.transpose

    @classmethod
    def get_all(cls, collection):
        try:
            return [cls(**elem) for elem in db.find_all(collection, {})]
        except TypeError:
            return False

    @staticmethod
    def get_all_df(collection):
        r = db.find(collection, {})
        if not r:
            return False
        else:
            return pd.DataFrame(list(r))

    @classmethod
    def get_by_scanner(cls, collection, scanner):
        try:
            return [cls(**elem) for elem in db.find_all(collection, {'type': scanner})]
        except TypeError:
            return False

    @staticmethod
    def get_by_scanner_df(collection, scanner):
        r = db.find(collection, {'type': scanner})
        if not r:
            return False
        else:
            return pd.DataFrame(list(r))

    @classmethod
    def get_all_filtered(cls, collection, order_by='0', order_direction=1, limit_number=0, page=1, logical_expr='$or', search=None):
        if order_direction == 'asc':
            order_direction = 1
        elif order_direction == 'desc':
            order_direction = -1

        columns = {
            '0': '_id',
            '1': 'title',
            '2': 'description',
            '3': 'cvss',
            '4': 'category',
            '5': 'cve',
            '6': 'cwe',
            '7': 'similarity',
            '8': 'type',
            '9': 'refs',
            '10': 'dsk'
        }

        limit_number = int(limit_number)

        # TODO: mount query with search
        if search:
            query = {}
        else:
            query = {}

        # print('order by: {}'.format(order_by))
        # print('order_direction: {}'.format(order_direction))
        # print('limit number: {}'.format(limit_number))
        # print('page: {}'.format(page))

        try:
            r = [cls(**elem) for elem in db.find(collection, query,
                                                 order_by=columns[order_by],
                                                 order_direction=order_direction,
                                                 limit_number=limit_number,
                                                 page=int(page))]
        except TypeError:
            r = False

        print(r)

        return r

    @staticmethod
    def get_all_json(collection='mapped', order_by=None, order_direction=1, limit_number=0, page=1, search=None):
        plugins = Plugin.get_all_filtered(collection, order_by, order_direction, limit_number, page)
        data = []
        if not plugins:
            return False
        for p in plugins:
            data.append(p.jsonify())
        return data

    @staticmethod
    def count_plugins(collection, search=None):
        # TODO: mount query with search
        if search:
            pass
        else:
            query = {}

        return db.count(collection, query)


    def jsonify(self):
        return {
            'title': self.title,
            'description': self.description,
            'cvss': self.cvss,
            'category': self.category,
            'cve': self.cve,
            'cwe': self.cwe,
            'similarity': self.similarity,
            '_id': self._id,
            'type': self.type,
            'refs': self.refs,
            'dsk': self.dsk
        }

    def tokenize(self, attr):
        accepted = {
            'title': self.title,
            'description': self.description,
            'cve': self.cve,
            'cwe': self.cwe,
            'refs': self.refs,
            'dsk': self.dsk
        }
        matcher = {
            'title': r'\w+[-\w+]*',
            'description': r'\w+[-\w+]*',
            'cve': r'CVE[\s|-]\d+[\s|-]\d+'
        }

        if attr not in accepted.keys():
            return 'It is not possible to tokenize this plugin attribute.'

        tokenizer = RegexpTokenizer(matcher[attr])
        stop = stopwords.words('english')
        final = []
        if attr == 'title' or attr == 'description':
            intermediate = tokenizer.tokenize(accepted[attr])
            final = [i.lower() for i in intermediate if i not in stop]
        elif attr == 'cve':
            intermediate = tokenizer.tokenize(','.join(accepted[attr]))
            final = [i.lower().replace(' ', '-') for i in intermediate if i not in stop]

        return final

    def compare_title(self, plugin_b):
        '''
        Compares two plugin titles and return the similarity between them
        :param pluginB: Plugin object
        :return:
            plugin_b._id: String
            similarity: Float between 0 and 1
        '''

        s = fuzz.token_sort_ratio(self.title, plugin_b.title)

        # return plugin_b._id, s
        return 1, (s / 100.0)

    def compare_description(self, plugin_b):
        '''
        Compares two plugin description and return the similarity between them
        :param pluginB:
        :return:
            plugin_b._id: String
            similarity: Float between 0 and 1
        '''

        s = fuzz.token_set_ratio(self.description, plugin_b.description)

        #return plugin_b._id, s
        return 1, (s / 100.0)

    def compare_refs(self, plugin_b):

        ref_a = ','.join(self.refs['ref'])
        ref_b = ','.join(plugin_b.refs['ref'])

        s = fuzz.token_set_ratio(ref_a, ref_b)

        # return plugin_b._id, s
        return 1, (s / 100.0)

    def compare_cve(self, plugin_b):

        cves_a = ','.join(self.cve)
        cves_b = ','.join(plugin_b.cve)

        s = fuzz.token_set_ratio(cves_a, cves_b)

        # return plugin_b._id, s
        return 1, (s / 100.0)

    def update_similarity(self, plugin_b):

        # if self.type == plugin_b.type:
        #     return
        #
        # if plugin_b.dsk[0] in self.dsk:
        #     return False

        ct = self.compare_title(plugin_b)
        #cd = self.compare_description(plugin_b)
        if (self.cve[0] == '') or (plugin_b.cve[0] == ''):
            cc = (0, 0)
        else:
            cc = self.compare_cve(plugin_b)
        if (self.refs['ref'][0] == '') or (plugin_b.refs['ref'][0] == ''):
            cr = (0, 0)
        else:
            cr = self.compare_refs(plugin_b)

        r = (ct[1] + 2*cc[1] + 2*cr[1]) / (ct[0] + 2*cc[0] + 2*cr[0])

        # print('Title Similarity: {}'.format(ct[1]))
        # print('CVE Similarity: {}'.format(cc[1]))
        # print('Refs Similarity: {}'.format(cr[1]))

        return r

        # if plugin_b.type not in self.similarity.keys():
        #     self.similarity[plugin_b.type] = {}
        #
        # self.similarity[plugin_b.type][plugin_b.dsk[0]] = r
        #
        # db.remove('unmapped', {'_id': self._id})
        #
        # return self.save('mapped')

    def sort_matches(self, type):

        sort = sorted(self.similarity[type].items(), key=operator.itemgetter(1))
        sort.reverse()

        return sort


