class Example {
    private string saved;
    private string Value() { return "status"; }
    public void Set() { saved = "--version"; }
    public void Run() {
        string copy = Value();
        command.CommandText = "SELECT * FROM items WHERE name='" + copy + "'";
        string shell = "/bin/sh -c ";
        Process.Start(shell + saved);
    }
}
