class Example {
    void run(HttpServletRequest request) {
        String data = "known";
        statement.executeQuery("SELECT name FROM users WHERE name='" + data + "'");
        Runtime.getRuntime().exec("echo " + data);
        String destination = "/home";
        response.sendRedirect(destination);
    }
}
