class Example {
    void run(HttpServletRequest request) {
        if (enabled) {
            String[] names = "alice-bob".split("-");
            for (int i = 0; i < names.length; i++) {
                statement.executeQuery("SELECT name FROM users WHERE name='" + names[i] + "'");
            }
        }
        {
            String data = "known";
            statement.executeQuery("SELECT name FROM users WHERE name='" + data + "'");
        }
        {
            String data = "alice";
            statement.executeQuery("SELECT name FROM users WHERE name='" + data + "'");
        }
        if (enabled) {
            String command = "echo ready";
            Runtime.getRuntime().exec(command);
        }
    }
}
