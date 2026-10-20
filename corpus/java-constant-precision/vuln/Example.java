class Example {
    void run(HttpServletRequest request) {
        String data = request.getParameter("name");
        statement.executeQuery("SELECT name FROM users WHERE name='" + data + "'");
        Runtime.getRuntime().exec("echo " + data);
        response.sendRedirect(data);
    }
}
