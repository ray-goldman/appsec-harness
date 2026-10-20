import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class AccountDao {
    ResultSet find(Connection connection, HttpServletRequest request) throws SQLException {
        String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
        Statement st = connection.createStatement();
        return st.executeQuery(query);
    }
}
