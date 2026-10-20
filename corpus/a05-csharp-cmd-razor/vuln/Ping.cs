using System.Diagnostics;
public class Ping {
    public void Run(string host) { Process.Start("cmd.exe", "/c ping " + host); }
}
