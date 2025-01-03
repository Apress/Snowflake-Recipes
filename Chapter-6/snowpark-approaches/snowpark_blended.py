from snowflake.snowpark import Session
from snowflake.snowpark.functions import col
from snowflake.snowpark.functions import udf
from snowflake.snowpark.dataframe_reader import *
from snowflake.snowpark.functions import *
from snowflake.snowpark.window import *
from snowflake.snowpark.types import IntegerType

connection_parameters = {
    "account": "",
    "user": "",
    "password": "",
    "warehouse": "",
    "database":"COMMONS",   
    "schema":"UTILS"
}  

session = Session.builder.configs(connection_parameters).create()

DEFAULT_YEAR = 1995

# this function is pushed down as a UDF though this is a bad example since it is not a data heavy operation
# but this is registered to show the blended approach
@udf(name="calc_order_increase", is_permanent=True, stage_location="@client_code", replace=True)
def local_order_increase(order_y1: int, order_y2: int) -> float:
  return (order_y2-order_y1)*100/order_y1

# this function remains local
def get_order_increase(chosen_year: int) -> str:
    
    df_order_vol_chosen_year = session.sql("select count(*) as count from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = ?", params=[chosen_year])
    
    df_order_vol_base_year = session.sql("select count(*) as count from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = ?", params=[DEFAULT_YEAR])
    
    #this is when the query executes; lazy loading; collect returns an immutable named tuple
    order_vol_chosen_year = df_order_vol_chosen_year.collect()[0]['COUNT'] 
    order_vol_base_year = df_order_vol_base_year.collect()[0]['COUNT']
    
    res = session.sql("select calc_order_increase(?,?) as result",[order_vol_base_year, order_vol_chosen_year])
    
    # write any code you want to do local using any library here
    
    return res



result = get_order_increase(1996)
result.show()
session.close()

