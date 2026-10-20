import org.hibernate.Session;
import org.hibernate.query.Query;
import javax.servlet.http.HttpServletRequest;

public class AccountRepo {
    Query find(Session session, HttpServletRequest request) {
        Query q = session.createQuery("FROM accounts WHERE custID = :id");
        q.setParameter("id", request.getParameter("id"));
        return q;
    }
}
