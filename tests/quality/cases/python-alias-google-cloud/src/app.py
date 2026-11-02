from google.cloud import bigquery
import google.api_core

def run(client):
    return client.query('select 1')
