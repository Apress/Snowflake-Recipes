import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

# Create a Pandas DataFrame
# Read the CSV file into a Pandas DataFrame
df = pd.read_csv('customer_sample.csv')

# Display the first five rows of the DataFrame
print(df.head())

# Convert the Pandas DataFrame to a PyArrow table
table = pa.Table.from_pandas(df)

# Write the PyArrow table to a Parquet file
pq.write_table(table, 'customers.parquet')
