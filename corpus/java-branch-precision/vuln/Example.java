class Example {
  void selected(HttpServletRequest request) {
    int count = 106;
    String data;
    if ((7 * 42) - count > 200) {
      data = "known";
    } else {
      data = request.getParameter("name");
    }
    String sql = "SELECT * FROM users WHERE name='" + data + "'";
    statement.executeQuery("SELECT * FROM users WHERE name='" + data + "'");
  }
  void ternary(HttpServletRequest request) {
    int count = 86;
    String data = (7 * 42) - count > 200 ? request.getParameter("name") : "known";
    statement.executeQuery("SELECT * FROM users WHERE name='" + data + "'");
  }
  void choice(HttpServletRequest request) {
    String guess = "ABC";
    char target = guess.charAt(1);
    String data;
    switch (target) {
      case 'A': data = "known"; break;
      case 'B': data = request.getParameter("name"); break;
      default: data = "other";
    }
    statement.executeQuery("SELECT * FROM users WHERE name='" + data + "'");
  }
}
