from snowflake.core import Root


# Preping the connection parameters
# database, schema and warehosue are optional if the user has a default value set for each of these attributes
connection_parameters = {
    "account": "",
    "user": "",
    "password": "",
    "warehouse": "" 
}  


# Example using snowflake snowpark session object

import snowflake.snowpark 

session = snowflake.snowpark.Session.builder.configs(connection_parameters).create()  
root = Root(session)

databases = root.databases.iter(like="r%")
for database in databases:
  print(database.to_dict())

session.close()


# Example using snowflake python connector object

import snowflake.connector

connection = snowflake.connector.connect(**connection_parameters)
root = Root(connection)

databases = root.databases.iter(like="r%")
for database in databases:
  print(database.to_dict())

connection.close()