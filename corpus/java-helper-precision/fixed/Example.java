class Example {
  private String prefix(String value) { return "user-" + value; }
  void run(HttpServletRequest request) {
    String selected = prefix("service-account");
    statement.executeQuery("SELECT name FROM users WHERE name='" + selected + "'");
    Runtime.getRuntime().exec("echo " + selected);
  }
}
