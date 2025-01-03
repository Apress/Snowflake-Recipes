create or replace function calc_order_increase(order_y1 INTEGER, order_y2 INTEGER)
returns DOUBLE
language python
runtime_version = '3.8'
handler = 'main'
as
$$
def main(order_y1, order_y2):
  return (order_y2-order_y1)*100/order_y1
$$;


 
create or replace procedure get_order_increase(chosen_year int)
returns VARCHAR
language python
runtime_version = '3.8'
packages=('snowflake-snowpark-python')
handler = 'main'
as
$$

DEFAULT_YEAR = 1995;

def main(session, chosen_year):
    
    df_order_vol_chosen_year = session.sql("select count(*) as count from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = ?", params=[chosen_year])
    
    df_order_vol_base_year = session.sql("select count(*) as count from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = ?", params=[DEFAULT_YEAR])
    
    #this is when the query executes; lazy loading; collect returns an immutable named tuple
    order_vol_chosen_year = df_order_vol_chosen_year.collect()[0]['COUNT'] 
    order_vol_base_year = df_order_vol_base_year.collect()[0]['COUNT']
    
    res = session.sql("select calc_order_increase(?,?) as result",[order_vol_base_year, order_vol_chosen_year])
    
    return res.collect()[0]['RESULT']
$$;


# Test the procedure by running
call get_order_increase(1997);
