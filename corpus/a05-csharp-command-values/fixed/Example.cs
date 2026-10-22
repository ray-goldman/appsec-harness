using String = string;
class Example {
    private String Argument() { String value = "status"; return value; }
    public void Run(bool verbose) {
        Process.Start("cmd.exe", "/c " + Argument());
        string shell = "cmd /c ";
        string choice = verbose ? "help" : "status";
        Process.Start(shell + (choice ?? "version"));
    }
}
