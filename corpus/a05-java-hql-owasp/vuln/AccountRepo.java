import org.hibernate.Session;
import org.hibernate.query.Query;
import javax.servlet.http.HttpServletRequest;

public class AccountRepo {
    Query find(Session session, HttpServletRequest request) {
        return session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
    }
}
