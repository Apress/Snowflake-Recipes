import pandas as pd

# Create a Pandas DataFrame
# Read the CSV file into a Pandas DataFrame
df = pd.read_csv('customer_sample.csv')

# Convert the Pandas DataFrame to a JSON string
json_string = df.to_json(orient='records')

# Print the JSON string
print(json_string)

# Write the JSON string to a file
with open('customers.json', 'w') as f:
    f.write(json_string)