import javax.servlet.http.Cookie;
public class Cookies { Cookie c(String v) { Cookie c = new Cookie("SID", v); c.setHttpOnly(true); c.setSecure(true); return c; } }
