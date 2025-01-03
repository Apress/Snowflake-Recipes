#!/usr/bin/env python
from sqlalchemy import create_engine, select, Table, MetaData

engine = create_engine(
    'snowflake://{user}:{password}@{account_identifier}/{database}/'.format(
        user="",
        password="",
        account_identifier="",
        database='SNOWFLAKE_SAMPLE_DATA'
    )
)
try:
    # Create a metadata object
    metadata = MetaData()

    # Create a session
    session = engine.connect()

    # Reflect the table from the database
    orders = Table('ORDERS', metadata, autoload_with=engine, schema='TPCH_SF1')

    # Query the table
    stmt = select(orders.c.o_orderkey, orders.c.o_shippriority).where(orders.c.o_orderdate == "1995-05-30").where(orders.c.o_orderstatus == "F")

    print(stmt)

    for row in session.execute(stmt):
        print("o_orderkey: ", row.o_orderkey)
        print("o_shippriority: ", row.o_shippriority)
        print("---------")

finally:
    session.close()
    engine.dispose()