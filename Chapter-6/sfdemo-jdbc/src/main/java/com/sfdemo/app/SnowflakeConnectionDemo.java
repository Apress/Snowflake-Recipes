package com.sfdemo.app;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

/**
 * Below is a barebones example of using the JDBC connector
 * It example does not use any logging libraries and all logging is done using System.out println() function
 * You might need to add a JVM runtime argument if you face an error 
 * as noted in https://github.com/snowflakedb/snowflake-jdbc/issues/589
 * @author johneipe
 *
 */
public class SnowflakeConnectionDemo {

	public static void main(String[] args) throws SQLException  {
		
		Connection connection = null;
		Statement statement = null;
		
		
		try {
			System.out.println("Create JDBC connection");
		    connection = getConnection();
		    System.out.println("Done creating JDBC connection\n");

		    // create statement
		    System.out.println("Create JDBC statement");
		    statement = connection.createStatement();
		    System.out.println("Done creating JDBC statement\n");


		    // query the data
		    System.out.println("Query demo");
		    ResultSet resultSet = statement.executeQuery("select C_NAME, C_ACCTBAL from SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.CUSTOMER limit 10");
		    System.out.println("Metadata:");
		    System.out.println("================================");

		    // fetch metadata
		    ResultSetMetaData resultSetMetaData = resultSet.getMetaData();
		    System.out.println("Number of columns=" + resultSetMetaData.getColumnCount());
		    for (int colIdx = 0; colIdx < resultSetMetaData.getColumnCount(); colIdx++) {
		      System.out.println(
		          "Column " + colIdx + ": type=" + resultSetMetaData.getColumnTypeName(colIdx + 1));
		    }

		    // fetch data
		    System.out.println("\nData:");
		    System.out.println("================================");
		    int rowIdx = 0;

			while (resultSet.next()) {
				for (int colIdx = 1; colIdx < resultSetMetaData.getColumnCount()+1; colIdx++) {
			      System.out.println("row: " + rowIdx + ", column : " +colIdx + ", value: "+ resultSet.getString(colIdx));
			    }
			}
		} catch (SQLException e) {
			System.out.println("Exception raised while creating SQL connection and executing queries");
			e.printStackTrace();
		}
		finally {
		    statement.close();
		    connection.close();

		}


	}
	 private static Connection getConnection() throws SQLException {

		    // build connection properties
		    Properties properties = new Properties();
		    properties.put("user", ""); // replace "" with your user name
		    properties.put("password", ""); // replace "" with your password
		    properties.put("warehouse", ""); // replace "" with target warehouse name, optional if default is set for the user
		    properties.put("db", "SNOWFLAKE_SAMPLE_DATA"); // replace "" with target database name, optional if default is set for the user
		    properties.put("schema", "TPCH_SF1"); // replace "" with target schema name, optional if default is set for the user
		    //properties.put("tracing", "all"); // optional tracing property

		    // Replace <account_identifier> with your account identifier. See
		    // https://docs.snowflake.com/en/user-guide/admin-account-identifier.html
		    // for details.
		    String connectStr = "jdbc:snowflake://<account_identifier>.snowflakecomputing.com";
		    
		    return DriverManager.getConnection(connectStr, properties);
		  }

}
