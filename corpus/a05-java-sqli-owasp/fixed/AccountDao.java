import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class AccountDao {
    ResultSet find(Connection connection, HttpServletRequest request) throws SQLException {
        PreparedStatement ps = connection.prepareStatement("SELECT * FROM accounts WHERE custID = ?");
        ps.setString(1, request.getParameter("id"));
        return ps.executeQuery();
    }
}
