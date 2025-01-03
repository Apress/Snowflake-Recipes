
/** SQL UDFs - overloading approach and use of session variables **/
SET default_year = 1995;
    
create or replace function get_order_volume(chosen_year NUMBER)
returns NUMBER
AS
$$
    select count(*) from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = chosen_year
$$
;
create or replace function get_order_volume()
returns NUMBER
AS
$$
    select count(*) from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = $default_year
$$

/** SQL UDFs - Default argument approach **/

create or replace function get_order_volume(chosen_year NUMBER default 1995)
returns NUMBER
AS
$$
    select count(*) from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = chosen_year
$$
;

--test function
select get_order_volume();

/** SQL Procedures **/
create or replace procedure get_order_increase(chosen_year NUMBER)
returns FLOAT NOT NULL
language sql
execute as caller
as
$$
declare
    order_vol_base_year NUMBER DEFAULT 0;
    order_vol_chosen_year NUMBER DEFAULT 0;
    res1 RESULTSET DEFAULT (select get_order_volume(:chosen_year) as count); 
    res2 RESULTSET DEFAULT (select get_order_volume() as count); 
    c1 CURSOR for res1;
    c2 CURSOR for res2;
begin
    for row_variable in c1 do
        order_vol_base_year := row_variable.count;
    end for;
    for row_variable in c2 do
        order_vol_chosen_year := row_variable.count;
    end for;
return (order_vol_base_year-order_vol_chosen_year)*100/order_vol_base_year;
END;
$$
;

--Test the procedure by running,
call get_order_increase(1997);
