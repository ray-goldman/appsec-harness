using String = string;
class Example {
    private String Argument() { String value = Request.Query["command"]; return value; }
    public void Run(bool verbose) {
        Process.Start("cmd.exe", "/c " + Argument());
        string shell = "cmd /c ";
        string choice = verbose ? "help" : Request.Query["command"];
        Process.Start(shell + (choice ?? "version"));
    }
}
