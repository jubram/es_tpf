# coding: utf-8

import sys
import os

import pandas as pd
from tqdm import tqdm
from prettytable import PrettyTable

from config import DATA_DIR, DATABASE, COLLECTIONS
from database import Database as db
from parser import Parser
from plugin import Plugin

tqdm.pandas(desc='Progress')

class Utils(object):

    @staticmethod
    def open_csv(filename):
        """
            Open the CSV file containing the plugins.

            Input:
            filename (str) -- the filename, with the complete path,
                              for the file

            Output:
            reader -- the csv.reader object with the plugins
        """

        if filename.split('.')[-1].lower() != 'csv':
            return False

        try:
            df = pd.read_csv(filename)
            df = df.applymap(lambda field: field.replace('\\n', ' ') if type(field) is str else field)
            df.fillna('', inplace=True)
            return df
        except IOError:
            return None

    @staticmethod
    def progress(count, total, status=''):
        '''
        Here: https://gist.github.com/vladignatyev/06860ec2040cb497f0f3
        :param count:
        :param total:
        :param status:
        :return:
        '''

        bar_len = 60
        fille_len = int(round(bar_len * count / float(total)))

        percents = round(100.0 * count / float(total), 1)
        bar = '=' * fille_len + '-' * (bar_len - fille_len)

        sys.stdout.write('[%s] %s%s    %s\r' % (bar, percents, '%', status))
        sys.stdout.flush()

    @staticmethod
    def build_db(filename1='base-nessus-min', filename2='base-qualys-min', verbose=False):
        db.initialize(DATABASE)

        db.drop(COLLECTIONS[0])
        db.drop(COLLECTIONS[1])

        df1 = Utils.open_csv('{}/{}.csv'.format(DATA_DIR, filename1))
        if df1 is None:
            print('{} not found'.format(filename1))
            return False
        df2 = Utils.open_csv('{}/{}.csv'.format(DATA_DIR, filename2))
        if df2 is None:
            print('{} not found'.format(filename2))
            return False

        if verbose:
            print("Starting to parse the first file...")
            df1.progress_apply(Parser.nessus, axis=1)
        else:
            df1.apply(Parser.nessus, axis=1)
        if verbose: print("Done!\n")

        if verbose:
            print("Starting to parse the second file...")
            df2.progress_apply(Parser.qualys, axis=1)
        else:
            df2.apply(Parser.qualys, axis=1)
        if verbose: print("Done!\n")

        plugins1 = Plugin.get_all(COLLECTIONS[1])
        plugins2 = Plugin.get_all(COLLECTIONS[1])

        if verbose: print("Done!\n")

    @staticmethod
    def build_test_db():
        db.initialize(DATABASE)

        not_matching = Utils.open_csv('{}/not_match.csv'.format(DATA_DIR))
        for n, q in zip(not_matching.NID, not_matching.QID):
            n = Plugin.get_by_pid(COLLECTIONS[1], 'nessus-{}'.format(n))
            n.save(COLLECTIONS[2])
            q = Plugin.get_by_pid(COLLECTIONS[1], 'qualys-{}'.format(q))
            q.save(COLLECTIONS[2])

        mapping = Utils.open_csv('{}/matches.csv'.format(DATA_DIR))

        for i in range(len(mapping)):
            n = Plugin.get_by_pid(COLLECTIONS[1], 'nessus-{}'.format(mapping.NID[i]))
            n.save(COLLECTIONS[2])
            q = Plugin.get_by_pid(COLLECTIONS[1], 'qualys-{}'.format(mapping.QID[i]))
            q.save(COLLECTIONS[2])

    @staticmethod
    def print_results(tp, fp, fn, tn):
        table = PrettyTable(['Predicted', 'Positive', 'Negative'])
        row1 = ['Positive', tp, fp]
        row2 = ['Negative', fn, tn]
        table.add_row(row1)
        table.add_row(row2)

        print(table)

        accuracy = (tn + tp) / 275
        recall = tp / (tp + fn)
        precision = tp / (tp + fp)
        f1 = 2 * (precision * recall) / (precision + recall)
        fp_rate = fp / (fp + tn)

        print('Accuracy: {:.4f}'.format(accuracy))
        print('Precision: {:.4f}'.format(precision))
        print('Recall: {:.4f}'.format(recall))
        print('F1 Score: {:.4f}'.format(f1))

        print('False Positive Rate: {:.4f}'.format(fp_rate))

    @staticmethod
    def print_progress(**kwargs):

        n = kwargs.get('n')
        q = kwargs.get('q')
        s = kwargs.get('similarity')

        print('Nessus Title: {}\nQualys Title: {}'.format(n.title, q.title))
        print('Nessus CVEs: {}\nQualys CVEs: {}'.format(', '.join(n.cve), ', '.join(q.cve)))
        print('Nessus Refs: {}\nQualys Refs: {}'.format(', '.join(n.refs['ref']), ', '.join(q.refs['ref'])))
        print('Similarity: {}'.format(s))
        print('=+' * 10)