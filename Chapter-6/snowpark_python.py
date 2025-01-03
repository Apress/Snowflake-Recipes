# The Snowpark package is required for Python Worksheets. 
# You can add more packages by selecting them using the Packages control and then importing them.

import snowflake.snowpark as snowpark
from snowflake.snowpark.functions import col
from snowflake.snowpark.dataframe_reader import *
from snowflake.snowpark.functions import *
from snowflake.snowpark.window import *
from snowflake.snowpark.types import IntegerType

def main(session: snowpark.Session):

    # session object provides table() function to read from a mentioned table and select() function to select specific columns
    # below line of code creates a dataframe from tpch_sf1.lineitem table by selecting 2 columns and returns it in a DataFrame
    df_items = session.table("snowflake_sample_data.tpch_sf1.lineitem").select("l_quantity", year(col("l_receiptdate")).as_("receipt_year"), "l_partkey")
    
    # session object provides sql() function using which you could pass in any SQL command
    # below line of code runs sql command to select 2 columns from tpch_sf1.part table and returns it in a DataFrame
    df_parts = session.sql("select p_partkey, p_type from snowflake_sample_data.tpch_sf1.part")

    # join() function lets you perform a join (defaults to inner join unless specified) with the current DataFrame with another DataFrame (right) on a list of columns (on).
    # below line of code joins the 2 Dataframes created above on the "partkey" and renames "p_type" column as "product_type"
    df = df_items.join(df_parts,df_items.col("l_partkey") == df_parts.col("p_partkey")).select("receipt_year", "l_quantity", df_parts["p_type"].as_("product_type"))

    # group_by() function groups rows by the columns specified by expressions (similar to GROUP BY in SQL)
    # below line of code groups the dataset by "receipt_year" and "product_type" to aggregate on "l_quantity"
    # additionally "l_quantity" column is renamed as "quantity"
    df = df.group_by("receipt_year","product_type").agg(sum("l_quantity").as_("quantity"))

    # with_column() funtion lets you engineer and construct new columns
    # below line of code adds a new column rownum by creating a unique row number for each row within the window partition.
    df = df.with_column("rownum", row_number().over(Window.partition_by(col("receipt_year")).order_by(col("quantity").desc())))

    # below code selects specific columns from the Dataframes, does a casting for quantity and filters the top 3 rows using the rownum column 
    df = df.select( "receipt_year", "product_type", cast(df["quantity"], IntegerType()).as_("quantity"), "rownum").filter(col("rownum")<=3).order_by("receipt_year", col("quantity").desc())

    # finally we remove the rownum column as it offers no business value
    df = df.drop("rownum")
    
    return df