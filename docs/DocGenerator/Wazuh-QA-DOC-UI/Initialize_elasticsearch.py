import os
import re
import json
import requests
from elasticsearch import Elasticsearch, helpers

PATH="data"
INDEX = "qa-doc"

class Initialize_elasticsearch:
    def __init__(self):
        self.header = { "index" : { "_index" : INDEX, "_type" : "_doc" } }
        self.regex = ".*json"
        self.files = self.get_files()
        self.es = Elasticsearch()
        self.output = []

    def test_connection(self):
        try:
            res = requests.get("http://localhost:9200/_cluster/health")
            if res.status_code == 200:
                return True
        except Exception as e:
            print(e)
            return False

    def get_files(self):
        r = re.compile(self.regex)
        return list(filter(r.match, os.listdir(PATH)))

    def read_files_content(self):
        for file in self.files:
            with open(os.path.join(PATH, file)) as f:
                lines = json.load(f)
                self.output.append(lines)

    def remove_index(self):
        self.es.indices.delete(index=INDEX, ignore=[400, 404])

    def index_data(self):
        self.test_connection()
        self.get_files()
        self.read_files_content()
        self.remove_index()
        helpers.bulk(self.es, self.output, index=INDEX)


init=Initialize_elasticsearch()
init.index_data()
