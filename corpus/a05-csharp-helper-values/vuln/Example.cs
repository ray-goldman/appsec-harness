class Example {
    private string saved;
    private string Value(string input) { return input; }
    public void Set(string input) { saved = input; }
    public void Run(string input) {
        string copy = Value(input);
        command.CommandText = "SELECT * FROM items WHERE name='" + copy + "'";
        string shell = "/bin/sh -c ";
        Process.Start(shell + saved);
    }
}
