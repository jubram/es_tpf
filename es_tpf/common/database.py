import pymongo
from pymongo.errors import InvalidName


class Database(object):
    URI = 'mongodb://127.0.0.1:27017'
    DATABASE = None

    @staticmethod
    def initialize(db_name):
        client = pymongo.MongoClient(Database.URI)
        Database.DATABASE = client[db_name]
        return True
    
    @staticmethod
    def get_collections():
        return Database.DATABASE.collection_names()

    @staticmethod
    def get_collections():
        return Database.DATABASE.collection_names(include_system_collections=False)

    @staticmethod
    def insert(collection, data):
        try:
            Database.DATABASE[collection].insert(data)
            return True
        except InvalidName:
            return False

    @staticmethod
    def update(collection, query, data):
        try:
            Database.DATABASE[collection].update(query, data, upsert=True)
            return True
        except InvalidName:
            return False

    @staticmethod
    def find_all(collection, query):
        try:
            return Database.DATABASE[collection].find(query)
        except InvalidName:
            return False

    @staticmethod
    def find(collection, query, **options):
        print('\n## DB ##')
        print('order by: {}'.format(options.get('order_by')))
        print('limit number: {}'.format(options.get('limit_number')))
        print('order direction: {}'.format(options.get('order_direction')))
        print('page: {}'.format(options.get('page')))
        print('query: {}'.format(query))
        print('## END DB ##\n')
        if options['order_by'] is None and options['limit_number'] == 0:
            try:
                return Database.DATABASE[collection].find(query)
            except InvalidName:
                return False
        elif options['order_by'] and options['limit_number'] == 0:
            try:
                return Database.DATABASE[collection].find(query).sort(options['order_by'], options['order_direction'])
            except InvalidName:
                return False
        elif options['order_by'] is None and options['limit_number'] > 0:
            try:
                return Database.DATABASE[collection].find(query).skip((options['page']-1)*options['limit_number']).limit(options['limit_number'])
            except InvalidName:
                return False
        elif options['order_by'] and options['limit_number'] > 0:
            try:
                return Database.DATABASE[collection].find(query).sort(options['order_by'], options['order_direction']).skip((options['page']-1)*options['limit_number']).limit(options['limit_number'])
            except InvalidName:
                return False

    @staticmethod
    def count(collection, query):
        return Database.DATABASE[collection].find(query).count()

    @staticmethod
    def find_one(collection, query):
        try:
            return Database.DATABASE[collection].find_one(query)
        except InvalidName:
            return False

    @staticmethod
    def remove(collection, query):
        try:
            Database.DATABASE[collection].remove(query)
            return True
        except InvalidName:
            return False

    @staticmethod
    def drop(collection):
        try:
            Database.DATABASE[collection].drop()
            return True
        except InvalidName:
            return False