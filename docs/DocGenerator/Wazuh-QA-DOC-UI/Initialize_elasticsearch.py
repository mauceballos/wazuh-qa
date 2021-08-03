import os
import re
import json
import requests
from elasticsearch import Elasticsearch, helpers

PATH="data"
INDEX = "qa-doc"

class Initialize_elasticsearch:
    def __init__(self):
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
        delete=self.es.indices.delete(index=INDEX, ignore=[400, 404])
        print(f'Delete index {INDEX}\n {delete}\n')

    def index_data(self):
        self.test_connection()
        self.get_files()
        self.read_files_content()
        if self.test_connection():
            self.remove_index()
            print("Indexing data...\n")
            helpers.bulk(self.es, self.output, index=INDEX)
            out=json.dumps(self.es.cluster.health(wait_for_status='yellow', request_timeout=1), indent=4)
            print(out)


init=Initialize_elasticsearch()
init.index_data()
