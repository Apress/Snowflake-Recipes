
-- Demo Configuration

CREATE 
USER 
IF NOT EXISTS
	JDOE
	PASSWORD = 'P@55w0rd' 
	LOGIN_NAME = 'JDOE' 
	DISPLAY_NAME = 'Jane Doe' 
	FIRST_NAME = 'Jane' 
	LAST_NAME = 'Doe'
	EMAIL = 'jane.doe@fakemail.com'
	DEFAULT_ROLE = 'FINANCE_ADMIN'
	DEFAULT_WAREHOUSE = 'COMPUTE_WH'
	TIMEZONE = 'UTC'
	MUST_CHANGE_PASSWORD = FALSE
	DISABLED = FALSE
	TIMESTAMP_DAY_IS_ALWAYS_24H = FALSE
	COMMENT = '[{"DEPARTMENT":"Pulmonology"}, {"ROLE":"FINANCE_ADMIN"}]'
;  


use role accountadmin;
-- Setup Example
-- Create a healthcare database
CREATE DATABASE healthcare_db;

-- Switch to the healthcare database
USE DATABASE healthcare_db;

-- Create a patient schema
CREATE SCHEMA finance;

-- Switch to the patient schema
USE SCHEMA finance;

-- Create a healthcare claims table
CREATE TABLE IF NOT EXISTS claims (
    claim_id INTEGER,
    patient_id INTEGER,
    patient_first_name VARCHAR,
    patient_last_name VARCHAR,
    patient_ssn VARCHAR,
    diagnosis VARCHAR,
    treatment VARCHAR,
    date_of_service DATE,
    department VARCHAR
);

-- Add sample data to the claims table
INSERT INTO claims (claim_id, patient_id, patient_first_name, patient_last_name, patient_ssn, diagnosis, treatment, date_of_service, department)
VALUES
(1, 101, 'John', 'Doe', '123-45-6789', 'Influenza', 'Antibiotics', '2022-02-01', 'Primary Care'),
(2, 102, 'Jane', 'Smith', '987-65-4321', 'Sprained Ankle', 'Pain Medication', '2022-02-02', 'Orthopedics'),
(3, 103, 'Robert', 'Johnson', '456-78-9123', 'Pneumonia', 'Oxygen Therapy', '2022-02-03', 'Pulmonology'),
(4, 104, 'Emily', 'Davis', '789-12-3456', 'Heart Attack', 'Angioplasty', '2022-02-04', 'Cardiology'),
(5, 105, 'David', 'Miller', '234-56-7891', 'Migraine', 'Prescription Medication', '2022-02-05', 'Neurology'),
(6, 106, 'Sophia', 'Wilson', '321-54-9876', 'Broken Arm', 'Cast', '2022-02-06', 'Orthopedics'),
(7, 107, 'Michael', 'Brown', '876-54-3219', 'Depression', 'Counseling', '2022-02-07', 'Psychiatry'),
(8, 108, 'Olivia', 'Garcia', '654-32-1987', 'Asthma', 'Inhaler', '2022-02-08', 'Pulmonology'),
(9, 109, 'William', 'Martinez', '219-87-6543', 'Stroke', 'Rehabilitation', '2022-02-09', 'Neurology'),
(10, 110, 'Ava', 'Lopez', '987-65-4320', 'Broken Leg', 'Surgery', '2022-02-10', 'Orthopedics'),
(11, 111, 'Leah', 'Nguyen', '321-54-9879', 'Flu', 'Antiviral Medication', '2022-05-09', 'Primary Care'),
(12, 112, 'Isabella', 'Lee', '876-54-3210', 'Broken Nose', 'Surgery', '2022-05-10', 'ENT');

SELECT 
    claim_id, 
    patient_id, 
    patient_first_name, 
    patient_last_name, 
    patient_ssn, diagnosis, 
    treatment, 
    date_of_service, 
    department 
FROM healthcare_db.finance.claims;

use role securityadmin;
-- Create a role for healthcare analysts with access to diagnosis and treatment data
CREATE ROLE finance_analyst;

-- Grant select access to diagnosis and treatment columns for finance_analyst role
GRANT SELECT ON TABLE healthcare_db.finance.claims TO ROLE finance_analyst;
grant usage on database healthcare_db to role finance_analyst;
grant usage on schema healthcare_db.finance to role finance_analyst;
GRANT USAGE, OPERATE on WAREHOUSE compute_wh TO ROLE finance_analyst;
grant role finance_analyst to user ddayton;
use role finance_analyst;
select * from healthcare_db.finance.claims;


-- Create a role for healthcare administrators with access to all data
CREATE ROLE finance_admin;
-- Grant select access to all columns for healthcare_admin role
GRANT SELECT ON TABLE healthcare_db.finance.claims TO ROLE finance_admin;
grant usage on database healthcare_db to role finance_admin;
grant usage on schema healthcare_db.finance to role finance_admin;
GRANT USAGE, OPERATE on WAREHOUSE compute_wh TO ROLE finance_admin;
grant role finance_admin to user ddayton;
grant role finance_admin to user JDOE;
use role finance_admin;
select * from healthcare_db.finance.claims;

SHOW GRANTS to ROLE finance_analyst;

-- Demo Code
-- COLUMN LEVEL SECURITY: MASKING POLICIES
-- Create a generic masking policy to mask string values 
CREATE OR REPLACE MASKING POLICY masked_string AS (val string) returns string ->
    CASE
      WHEN current_role() in ('FINANCE_ADMIN') THEN val
      ELSE '********'
    END;

-- Add generic masking policy to patient_first_name, patient_last_name, diagnosis, and treatment columns
alter table healthcare_db.finance.claims modify column patient_first_name set masking policy masked_string;
alter table healthcare_db.finance.claims modify column patient_last_name set masking policy masked_string;
alter table healthcare_db.finance.claims modify column diagnosis set masking policy masked_string;
alter table healthcare_db.finance.claims modify column treatment set masking policy masked_string;

-- Create a SSN masking policy to mask SSN or return last 4 
CREATE OR REPLACE MASKING POLICY masked_ssn AS (val string) returns string ->
  CASE
    WHEN current_role() in ('FINANCE_ADMIN') THEN REGEXP_REPLACE(val,'((\\d{3})-(\\d{2})-(\\d{4}))', '***-**-\\4')
    ELSE '*********'
  END;

-- Add ssn masking policy to patient_ssn column
alter table healthcare_db.finance.claims modify column patient_ssn set masking policy masked_ssn;

-- Test analyst role
use role finance_analyst;
SELECT 
    claim_id, 
    patient_id, 
    patient_first_name, 
    patient_last_name, 
    patient_ssn, 
    diagnosis, 
    treatment, 
    date_of_service, 
    department 
FROM healthcare_db.finance.claims;

-- Test admin role
use role finance_admin;
SELECT 
    claim_id, 
    patient_id, 
    patient_first_name, 
    patient_last_name, 
    patient_ssn, 
    diagnosis, 
    treatment, 
    date_of_service, 
    department 
FROM healthcare_db.finance.claims;

-- Create a column level security policy to restrict access to the department column for users
-- create cross reference table for users and departments
create table department_user_xref (
    user varchar,
    department varchar,
    insert_date datetime,
    update_date datetime
);

-- seed table with known users
INSERT INTO department_user_xref (user, department, insert_date, update_date)
VALUES
('JDOE', 'Pulmonology', current_timestamp(), current_timestamp());

-- Create dept policy only return rows specific to the users department
create or replace row access policy dept_policy as (department_value varchar) returns boolean ->
    exists (select 1 
            from healthcare_db.finance.department_user_xref
            where user = current_user()
              and department = department_value);

-- add the row policy to the table
alter table healthcare_db.finance.claims add row access policy dept_policy on (department);

-- Test row access policy and masking policies together
use role finance_analyst;
select * from healthcare_db.finance.claims;

use role finance_admin;
select * from healthcare_db.finance.claims;

-- Data Classification
-- Apply privacy classification
select system$get_tag_allowed_values('snowflake.core.privacy_category');

ALTER TABLE healthcare_db.finance.claims
  SET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY='SENSITIVE';

ALTER TABLE healthcare_db.finance.claims
  MODIFY COLUMN patient_ssn
  SET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY = 'IDENTIFIER';

-- Apply semantic classification
select system$get_tag_allowed_values('snowflake.core.semantic_category');

ALTER TABLE healthcare_db.finance.claims
  MODIFY COLUMN patient_first_name
  SET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY='NAME';

ALTER TABLE healthcare_db.finance.claims
  MODIFY COLUMN patient_last_name
  SET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY='NAME';

ALTER TABLE healthcare_db.finance.claims
  MODIFY COLUMN patient_ssn
  SET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY='US_SSN';

-- validate the classification tags have been applied
SELECT object_database, object_schema, object_name, column_name, level, tag_name, tag_value
from table(healthcare_db.information_schema.tag_references_all_columns('claims','table'))
order by tag_name;

