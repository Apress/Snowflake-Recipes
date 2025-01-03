import pandas as pd
import pyarrow as pa
import pyarrow.orc as orc

# Create a Pandas DataFrame
# Read the CSV file into a Pandas DataFrame
df = pd.read_csv('customer_sample.csv')

# Display the first five rows of the DataFrame
print(df.head())

# Convert the Pandas DataFrame to a PyArrow table
table = pa.Table.from_pandas(df)


# Write the PyArrow table to an ORC file
with open('customers.orc', 'wb') as f:
    orc.write_table(table, f)
