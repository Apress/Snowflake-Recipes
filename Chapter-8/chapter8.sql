-- Demo Code 8-1
-- Failsafe and Time Travel

use role sysadmin;

-- Create a retail database
CREATE DATABASE retail_db;

-- Switch to the retail database
USE DATABASE retail_db;

-- Create a sales schema
CREATE SCHEMA sales;

-- Switch to the sales schema
USE SCHEMA sales;

-- Create a transactional sales table
CREATE TABLE IF NOT EXISTS retail_db.sales.fact_sales_transaction (
    transaction_id INT,
    product_id INT,
    customer_id INT,
    sale_date DATE,
    quantity INT,
    unit_price DECIMAL(10, 2),
    total_amount DECIMAL(12, 2),
    discount DECIMAL(5, 2),
    tax DECIMAL(5, 2),
    payment_method VARCHAR(50),
    shipping_address VARCHAR(200),
    sales_representative VARCHAR(100),
    transaction_status VARCHAR(20),
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- Add sample data to the fact table
INSERT INTO fact_sales_transaction (
    transaction_id,
    product_id,
    customer_id,
    sale_date,
    quantity,
    unit_price,
    total_amount,
    discount,
    tax,
    payment_method,
    shipping_address,
    sales_representative,
    transaction_status,
    created_at,
    updated_at
)
VALUES
    (1, 101, 201, '2023-05-14', 3, 25.99, 77.97, 5.00, 3.50, 'Credit Card', '123 Main St, City A', 'John Smith', 'Completed', '2023-05-14 10:00:00', '2023-05-14 10:00:00'),
    (2, 102, 202, '2023-05-14', 2, 19.99, 39.98, 2.00, 1.50, 'PayPal', '456 Elm St, City B', 'Jane Doe', 'Completed', '2023-05-14 11:30:00', '2023-05-14 11:30:00'),
    (3, 103, 203, '2023-05-15', 1, 9.99, 9.99, 0.00, 0.50, 'Cash', '789 Oak St, City C', 'Mike Johnson', 'Completed', '2023-05-15 09:45:00', '2023-05-15 09:45:00'),
    (4, 104, 201, '2023-05-15', 5, 12.50, 62.50, 2.50, 2.00, 'Credit Card', '321 Maple St, City D', 'Sarah Williams', 'Completed', '2023-05-15 14:20:00', '2023-05-15 14:20:00'),
    (5, 105, 204, '2023-05-16', 3, 8.75, 26.25, 1.25, 1.00, 'PayPal', '789 Pine St, City E', 'David Lee', 'Completed', '2023-05-16 16:05:00', '2023-05-16 16:05:00');

select 
    TRANSACTION_ID, 
    PRODUCT_ID, 
    CUSTOMER_ID, 
    SALE_DATE, 
    QUANTITY, 
    UNIT_PRICE, 
    TOTAL_AMOUNT, 
    DISCOUNT, 
    TAX, 
    PAYMENT_METHOD, 
    SHIPPING_ADDRESS, 
    SALES_REPRESENTATIVE, 
    TRANSACTION_STATUS, 
    CREATED_AT, 
    UPDATED_AT
from fact_sales_transaction;

--create config table
CREATE TABLE IF NOT EXISTS retail_db.sales.tax_rates_lookup (
    state_code VARCHAR(2) NOT NULL,
    county VARCHAR(100),
    city VARCHAR(100),
    tax_rate DECIMAL(5, 2) NOT NULL,
    effective_date DATE NOT NULL,
    expiration_date DATE
);

-- Add sample data to the config table
INSERT INTO tax_rates_lookup (state_code, county, city, tax_rate, effective_date, expiration_date)
VALUES
    ('CA', 'Los Angeles', 'Los Angeles', 9.50, '2023-01-01', '2023-12-31'),
    ('CA', 'Orange', 'Irvine', 8.75, '2023-01-01', '2023-06-30'),
    ('NY', NULL, NULL, 8.88, '2023-01-01', NULL),
    ('TX', 'Harris', 'Houston', 8.25, '2023-01-01', '2023-12-31'),
    ('TX', 'Dallas', 'Dallas', 8.25, '2023-01-01', '2023-12-31');

select 
    state_code,
    county,
    city,
    tax_rate,
    effective_date,
    expiration_date
from tax_rates_lookup;

use role securityadmin;

-- Create a role for healthcare analysts with access to diagnosis and treatment data
CREATE ROLE supply_chain_analyst;

-- Grant select access to diagnosis and treatment columns for finance_analyst role
GRANT SELECT ON TABLE retail_db.sales.fact_sales_transaction TO ROLE supply_chain_analyst;
GRANT SELECT ON TABLE retail_db.sales.tax_rates_lookup TO ROLE supply_chain_analyst;
GRANT ALL on database retail_db to role sysadmin;
GRANT ALL on schema retail_db.sales to role sysadmin;
GRANT ALL ON TABLE retail_db.sales.fact_sales_transaction TO ROLE sysadmin;
GRANT ALL ON TABLE retail_db.sales.tax_rates_lookup TO ROLE sysadmin;

grant usage on database retail_db to role supply_chain_analyst;
grant usage on schema retail_db.sales to role supply_chain_analyst;
GRANT USAGE, OPERATE on WAREHOUSE compute_wh TO ROLE supply_chain_analyst;


select * from RETAIL_DB.SALES.FACT_SALES_TRANSACTION;
select * from RETAIL_DB.SALES.TAX_RATES_LOOKUP;

SHOW GRANTS to ROLE supply_chain_analyst;

use role sysadmin;
use database retail_db;
use schema sales; 

drop table tax_rates_lookup;

use role supply_chain_analyst;

select 
    state_code,
    county,
    city,
    tax_rate,
    effective_date,
    expiration_date
from tax_rates_lookup;

SHOW TABLES HISTORY LIKE 'tax%' IN retail_db.sales;

use role sysadmin;
use database retail_db;
use schema sales;

UNDROP TABLE tax_rates_lookup;

SHOW TABLES HISTORY LIKE 'tax%' IN retail_db.sales;

use role supply_chain_analyst;

select 
    state_code,
    county,
    city,
    tax_rate,
    effective_date,
    expiration_date
from tax_rates_lookup;

use role sysadmin;
use database retail_db;
use schema sales; 

update fact_sales_transaction set tax = 10;

use role supply_chain_analyst;

select distinct transaction_id, tax from fact_sales_transaction;

use role sysadmin;
use database retail_db;
use schema sales; 

create table restored_fact_sales_transaction clone fact_sales_transaction
 before (statement => '01add13d-0001-b4ad-001b-49870001879a');

select distinct transaction_id, tax from restored_fact_sales_transaction;

alter table fact_sales_transaction rename to bad_fact_sales_transaction;
alter table restored_fact_sales_transaction rename to fact_sales_transaction

use role supply_chain_analyst;

select 
    TRANSACTION_ID, 
    SALE_DATE, 
    QUANTITY, 
    UNIT_PRICE, 
    TOTAL_AMOUNT, 
    TAX, 
    CREATED_AT, 
    UPDATED_AT
from fact_sales_transaction;

-- Demo Code 8-2
-- Snowflake Clones

--setup
use role sysadmin;

create database PROD_FINANCE;
create database QA_FINANCE;

create schema PROD_FINANCE.BILLING;
create schema QA_FINANCE.BILLING;

CREATE TABLE PROD_FINANCE.BILLING.INVOICES (
    invoice_id INT PRIMARY KEY,
    customer_id varchar(20) NOT NULL,
    invoice_date DATE NOT NULL,
    due_date DATE NOT NULL,
    total_amount DECIMAL(10, 2) NOT NULL,
    payment_status VARCHAR(20) DEFAULT 'Pending',
    payment_date DATE,
    payment_amount DECIMAL(10, 2),
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

INSERT INTO PROD_FINANCE.BILLING.INVOICES (invoice_id, customer_id, invoice_date, due_date, total_amount, payment_status, payment_date, payment_amount)
VALUES
    (1, 101, '2023-05-01', '2023-05-15', 250.00, 'Paid', '2023-05-10', 250.00),
    (2, 102, '2023-05-02', '2023-05-16', 350.00, 'Pending', NULL, NULL),
    (3, 103, '2023-05-03', '2023-05-17', 450.00, 'Pending', NULL, NULL),
    (4, 104, '2023-05-04', '2023-05-18', 550.00, 'Paid', '2023-05-12', 550.00),
    (5, 105, '2023-05-05', '2023-05-19', 150.00, 'Paid', '2023-05-08', 150.00);


CREATE OR REPLACE MASKING POLICY PROD_FINANCE.BILLING.masked_string AS (val string) returns string ->
    CASE
      WHEN current_role() in ('FINANCE_ADMIN') THEN val
      ELSE '********'
    END;

alter table PROD_FINANCE.BILLING.INVOICES modify column customer_id set masking policy PROD_FINANCE.BILLING.masked_string;

-- set permissions
use role securityadmin;

CREATE ROLE qa_engineer;

GRANT SELECT ON future TABLES in schema PROD_FINANCE.BILLING TO ROLE qa_engineer;
grant usage on database prod_finance to role qa_engineer;
grant usage on schema prod_finance.billing to role qa_engineer;
grant usage on future schemas in database prod_finance to role qa_engineer;
GRANT SELECT ON future TABLES in schema QA_FINANCE.BILLING TO ROLE qa_engineer;

grant usage on database qa_finance to role qa_engineer;
grant all on schema qa_finance.billing to role qa_engineer;
grant all on future schemas in database qa_finance to role qa_engineer;
grant all on all tables in database qa_finance to role qa_engineer;

-- demo
use role qa_engineer;

desc table PROD_FINANCE.BILLING.INVOICES;

select 
    INVOICE_ID, 
    CUSTOMER_ID, 
    INVOICE_DATE, 
    DUE_DATE, 
    TOTAL_AMOUNT, 
    PAYMENT_STATUS, 
    PAYMENT_DATE, 
    PAYMENT_AMOUNT, 
    CREATED_AT, 
    UPDATED_AT
from PROD_FINANCE.BILLING.INVOICES;

desc masking policy masked_string;

create or replace schema QA_FINANCE.BILLING clone PROD_FINANCE.BILLING;

use role qa_engineer;
select 
    INVOICE_ID, 
    CUSTOMER_ID, 
    INVOICE_DATE, 
    DUE_DATE, 
    TOTAL_AMOUNT, 
    PAYMENT_STATUS, 
    PAYMENT_DATE, 
    PAYMENT_AMOUNT, 
    CREATED_AT, 
    UPDATED_AT
from QA_FINANCE.BILLING.INVOICES;

desc table QA_FINANCE.BILLING.INVOICES;

use role accountadmin;

select * from QA_FINANCE.INFORMATION_SCHEMA.TABLE_STORAGE_METRICS 
where table_schema = 'BILLING' 
    and clone_group_id = 4108
    and schema_dropped is null
order by table_catalog;

use role qa_engineer;

delete from QA_FINANCE.BILLING.INVOICES where invoice_id = 3;

update QA_FINANCE.BILLING.INVOICES
    set payment_status = 'Paid',
        payment_date = current_date(),
        payment_amount = '350.00'
    where invoice_id = 2;

insert into QA_FINANCE.BILLING.INVOICES (invoice_id, 
                                            customer_id, 
                                            invoice_date, 
                                            due_date, 
                                            total_amount, 
                                            payment_status, 
                                            payment_date, 
                                            payment_amount)
VALUES
    (6, 601, '2023-05-16', '2023-05-30', 275.00, 'Pending', null, null);

select 
    INVOICE_ID, 
    CUSTOMER_ID, 
    INVOICE_DATE, 
    DUE_DATE, 
    TOTAL_AMOUNT, 
    PAYMENT_STATUS, 
    PAYMENT_DATE, 
    PAYMENT_AMOUNT, 
    CREATED_AT, 
    UPDATED_AT
from QA_FINANCE.BILLING.INVOICES;

use role accountadmin;

select * from QA_FINANCE.INFORMATION_SCHEMA.TABLE_STORAGE_METRICS 
where table_schema = 'BILLING' 
    and clone_group_id = 4108
    and schema_dropped is null
order by table_catalog;

-- Demo Code 8-3
-- Account Replication and Failover (Disaster Recovery)

-- Enable replication on all accounts

USE ROLE ORGADMIN;

SHOW ORGANIZATION ACCOUNTS;

SELECT SYSTEM$GLOBAL_ACCOUNT_SET_PARAMETER('HADKYDE.VZB90068', 'ENABLE_ACCOUNT_DATABASE_REPLICATION', 'true');
SELECT SYSTEM$GLOBAL_ACCOUNT_SET_PARAMETER('HADKYDE.SECONDARY', 'ENABLE_ACCOUNT_DATABASE_REPLICATION', 'true');
SELECT SYSTEM$GLOBAL_ACCOUNT_SET_PARAMETER('HADKYDE.TERTIARY', 'ENABLE_ACCOUNT_DATABASE_REPLICATION', 'true');

-- Setup Replication
use role accountadmin;

CREATE FAILOVER GROUP failover_grp
  OBJECT_TYPES = USERS, ROLES, WAREHOUSES, RESOURCE MONITORS, DATABASES
  ALLOWED_DATABASES = retail_db
  ALLOWED_ACCOUNTS = hadkyde.secondary,hadkyde.tertiary
  REPLICATION_SCHEDULE = '10 MINUTE';

SHOW FAILOVER GROUPS;


-- run on secondary account
CREATE FAILOVER GROUP failover_grp
  AS REPLICA OF hadkyde.vzb90068.failover_grp;

-- run on tertiary account
CREATE FAILOVER GROUP failover_grp
  AS REPLICA OF hadkyde.vzb90068.failover_grp;

-- manual refresh on secondary account
ALTER FAILOVER GROUP failover_grp REFRESH;

-- manual refresh on tertiary account
ALTER FAILOVER GROUP failover_grp REFRESH;


-- modify source database to demostrate replication

create or replace table retail_db.sales.repl_test (x varchar);
insert into retail_db.sales.repl_test (x) values ('test');
select x from retail_db.sales.repl_test;

-- run on seconary account to set as primary
ALTER FAILOVER GROUP failover_grp PRIMARY;

-- modify table on secondary account
insert into retail_db.sales.repl_test (x) values ('secondary test');
select x from retail_db.sales.repl_test;


-- Demo Code 8-4
-- Application Redirect (Business Continuity)
-- drop connection connection_grp;
-- run on source account


CREATE CONNECTION IF NOT EXISTS connection_grp;

-- allow secondary account to be added as replica
ALTER CONNECTION connection_grp ENABLE FAILOVER TO ACCOUNTS hadkyde.secondary;

-- show connections
SHOW CONNECTIONS;

-- run on secondary account
CREATE CONNECTION connection_grp AS REPLICA OF hadkyde.vzb90068.connection_grp;

-- trigger redirect to replica on secondary account
ALTER CONNECTION connection_grp PRIMARY;