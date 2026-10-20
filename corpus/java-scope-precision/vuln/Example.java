class Example {
    void run(HttpServletRequest request) {
        if (enabled) {
            String[] names = request.getParameter("names").split("-");
            for (int i = 0; i < names.length; i++) {
                statement.executeQuery("SELECT name FROM users WHERE name='" + names[i] + "'");
            }
        }
        {
            String data = "known";
            statement.executeQuery("SELECT name FROM users WHERE name='" + data + "'");
        }
        {
            String data = request.getParameter("name");
            statement.executeQuery("SELECT name FROM users WHERE name='" + data + "'");
        }
        if (enabled) {
            String command = request.getParameter("command");
            Runtime.getRuntime().exec(command);
        }
    }
}
