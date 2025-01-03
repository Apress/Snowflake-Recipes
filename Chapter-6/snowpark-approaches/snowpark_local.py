from snowflake.snowpark import Session


connection_parameters = {
    "account": "",
    "user": "",
    "password": "",
    "warehouse": ""
}  

session = Session.builder.configs(connection_parameters).create()

DEFAULT_YEAR = 1995


def local_order_increase(order_y1: int, order_y2: int) -> float:
    return (order_y2-order_y1)*100/order_y1

def get_order_increase(chosen_year: int) -> float:
    
    df_order_vol_chosen_year = session.sql("select count(*) as count from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = ?", params=[chosen_year])
    
    df_order_vol_base_year = session.sql("select count(*) as count from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = ?", params=[DEFAULT_YEAR])
    
    #this is when the query executes; lazy loading; collect returns an immutable named tuple
    order_vol_chosen_year = df_order_vol_chosen_year.collect()[0]['COUNT'] 
    order_vol_base_year = df_order_vol_base_year.collect()[0]['COUNT']
    
    return local_order_increase(order_vol_base_year,order_vol_chosen_year)



res = get_order_increase(1996)
print(res)
session.close()

