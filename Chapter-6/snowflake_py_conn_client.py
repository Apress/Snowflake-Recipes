import snowflake.connector

# A Connection object holds the connection and session information to keep the database connection active.
# database, schema and warehosue are optional if the user has a default value set for each of these attributes
conn = snowflake.connector.connect(
    user='',
    password='',
    account='',
    warehouse='',
    database='',
    schema=''
    )

#
## A Cursor object represents a database cursor for execute and fetch operations. 
## Each cursor has its own attributes, description and rowcount, such that cursors are isolated.
## That means we could create cursors multiple times from the same connection object and can be independently operated
#
print('------------------------------Using execute, for-iterator----------------------------------')
cur = conn.cursor()
try:
    cur.execute("select C_NAME, C_ACCTBAL from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.CUSTOMER limit 3")
    for (col1, col2) in cur:
        print('{0}, {1}'.format(col1, col2))
finally:
    cur.close()

#
## You may use utility functions like fetchone, fetchmany and fetchall 
## Use fetchone or fetchmany if the result set is too large to fit into memory.
## execute() function returns the reference to the same cursor object    
#
try:
    print('------------------------------Using execute, fetchone----------------------------------')
    cur = conn.cursor().execute("select C_NAME, C_ACCTBAL from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.CUSTOMER")
    col1, col2 =  cur.fetchone()
    print('{0}, {1}'.format(col1, col2))

    print('------------------------------Using execute, fetchmany----------------------------------')
    cur = conn.cursor().execute("select C_NAME, C_ACCTBAL from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.CUSTOMER")
    results = cur.fetchmany(3)
    for rec in results:
        print('%s, %s' % (rec[0], rec[1]))

    print('------------------------------Using execute, fetchall----------------------------------')
    cur = conn.cursor().execute("select C_NAME, C_ACCTBAL from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.CUSTOMER limit 3")
    results = cur.fetchall()
    for rec in results:
        print('%s, %s' % (rec[0], rec[1]))
finally:
    cur.close()

#
## Querying data using DictCursor
#
from snowflake.connector import DictCursor
print('------------------------------Using execute on DictCursor----------------------------------')
cur = conn.cursor(DictCursor)
try:
    cur.execute("select C_NAME, C_ACCTBAL from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.CUSTOMER limit 3")
    for rec in cur:
        print('{0}, {1}'.format(rec['C_NAME'], rec['C_ACCTBAL']))
finally:
    cur.close()

