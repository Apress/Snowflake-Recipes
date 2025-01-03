create or replace function calc_order_increase(order_y1 VARCHAR, order_y2 VARCHAR)
returns VARCHAR
language javascript
as
$$
    incr = (parseInt(ORDER_Y2)-parseInt(ORDER_Y1))*100/parseInt(ORDER_Y1);
    return incr.toString();
$$
;

create or replace procedure get_order_increase(chosen_year VARCHAR)
returns VARCHAR
language javascript
execute as caller
as
$$
    const DEFAULT_YEAR = 1995;
    
    /** Javascript stored procedures provides an implicit object called "snowflake" which can be used to execute SQL commands */
    res = snowflake
            .createStatement({
                sqlText: `select count(*) from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = ${chosen_year}::number`
            }).execute();
    /**
     * The res variable is a ResultSet object. You only see one row at a time in a ResultSet, just as you can see one row at a time in a SQL cursor.
     * Typically, after you retrieve a ResultSet, you iterate through it by repeating the following operations:
     **  Call next() to get the next row.
     **  Retrieve data from the current row by calling methods such as getColumnValue().
     */
    res.next();
    order_vol_chosen_year = res.getColumnValue(1);

    res = snowflake
            .createStatement({
                sqlText: `select count(*) from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.ORDERS where year(o_orderdate) = ${DEFAULT_YEAR}::number`
            }).execute();
    res.next();
    order_vol_base_year = res.getColumnValue(1);

    res = snowflake
            .createStatement({
                sqlText: `select calc_order_increase('${order_vol_base_year}', '${order_vol_chosen_year}')`
            }).execute();
    res.next();

    return res.getColumnValue(1);
    
$$
;

--Test the procedure by running
call get_order_increase(1997);

