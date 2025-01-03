
from confluent_kafka import Producer

def read_ccloud_config(config_file):
    conf = {}
    with open(config_file) as fh:
        for line in fh:
            line = line.strip()
            if len(line) != 0 and line[0] != "#":
                parameter, value = line.strip().split('=', 1)
                conf[parameter] = value.strip()
    return conf





import pandas as pd
import json

def csv_to_json_with_schema(csv_file, schema):
    # Read CSV into a pandas DataFrame
    df = pd.read_csv(csv_file, dtype=schema)
    
    # Convert DataFrame to JSON objects
    json_objects = df.to_dict(orient='records')
    
    return json_objects

# Sample CSV file path
csv_file_path = 'orders_sample.csv'

# Define the schema with column names and their respective data types
# Replace the 'dtype' values with the appropriate data types for your columns
# For example, 'int', 'float', 'str', 'datetime', etc.
schema = {
    'O_ORDERKEY': int,
    'O_CUSTKEY': int,
    'O_ORDERSTATUS': str,
    'O_TOTALPRICE': float,
    'O_ORDERDATE': str,
    'O_ORDERPRIORITY': str,
    'O_CLERK': str,
    'O_SHIPPRIORITY': int,
    'O_COMMENT': str
}

# Convert CSV to JSON objects with the defined schema
json_objects = csv_to_json_with_schema(csv_file_path, schema)

# Print the JSON objects if you need to debug
# print(json.dumps(json_objects, indent=2))

#
# You need to provide the kafka configuration via the properties file - kafka_client.properties
# It should have the following key value pairs
# bootstrap.servers=<confluent server>:<port>
# security.protocol=SASL_SSL
# sasl.mechanisms=PLAIN
# sasl.username=<secret id>
# sasl.password=<secret key>
#
# You should also subsitute the topic name with what is relavent to your configuration
# in this example it is "topic_tpch_orders"
#
producer = Producer(read_ccloud_config("kafka_client.properties"))
for json_object in json_objects:
    producer.produce("topic_tpch_orders", key=str(json_object['O_ORDERKEY']), value=json.dumps(json_object))
    print(str(json_object))
producer.flush() #We use the producer’s flush method here to ensure the message gets sent before the program exits.