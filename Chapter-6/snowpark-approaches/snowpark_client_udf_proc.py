from snowflake.snowpark.functions import udf,sproc
from snowflake.snowpark import Session
from snowflake.snowpark.dataframe_reader import *
from snowflake.snowpark.functions import *

connection_parameters = {
    "account": "",
    "user": "",
    "password": "",
    "warehouse": "", 
    "database":"COMMONS",
    "schema":"UTILS"
}  
session = Session.builder.configs(connection_parameters).create()  

@udf(name="calc_order_increase", is_permanent=True, stage_location="@client_code", replace=True)
def local_order_increase(order_y1: int, order_y2: int) -> float:
    return (order_y2-order_y1)*100/order_y1


DEFAULT_YEAR = 1995

@sproc(name="get_order_increase", is_permanent=True, stage_location="@client_code", replace=True, packages=["snowflake-snowpark-python"])
def local_get_order_increase(session: Session, chosen_year: int) -> str:
    
    df_order_vol_chosen_year = session.sql("select count(*) as count from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = ?", params=[chosen_year])
    
    df_order_vol_base_year = session.sql("select count(*) as count from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = ?", params=[DEFAULT_YEAR])
    
    #this is when the query executes; lazy loading; collect returns an immutable named tuple
    order_vol_chosen_year = df_order_vol_chosen_year.collect()[0]['COUNT'] 
    order_vol_base_year = df_order_vol_base_year.collect()[0]['COUNT']
    
    res = session.sql("select calc_order_increase(?,?) as result",[order_vol_base_year, order_vol_chosen_year])
    
    return res.collect()[0]['RESULT']

session.close()