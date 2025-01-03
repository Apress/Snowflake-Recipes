import pandas as pd
import fastavro

# Read the CSV file into a Pandas DataFrame
df = pd.read_csv('customer_sample.csv')

# Define the Avro schema
schema = {
    'namespace': 'customers',
    'type': 'record',
    'name': 'customers_record',
    'fields': [
        {'name': 'C_CUSTKEY', 'type': 'int'},
        {'name': 'C_NAME', 'type': 'string'},
        {'name': 'C_ADDRESS', 'type': 'string'},
        {'name': 'C_NATIONKEY', 'type': 'int'},
        {'name': 'C_PHONE', 'type': 'string'},
        {'name': 'C_ACCTBAL', 'type': 'double'},
        {'name': 'C_MKTSEGMENT', 'type': 'string'},
        {'name': 'C_COMMENT', 'type':'string'},
    ]
}

# Convert the Pandas DataFrame to a list of dicts
records = df.to_dict('records')

# Write the list of dicts to an Avro file
with open('customers.avro', 'wb') as f:
    fastavro.writer(f, schema, records)
