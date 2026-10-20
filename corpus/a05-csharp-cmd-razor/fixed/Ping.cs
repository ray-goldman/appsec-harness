using System.Diagnostics;
public class Ping {
    public void Run(string host) {
        var psi = new ProcessStartInfo("ping");
        psi.ArgumentList.Add(host);
        Process.Start(psi);
    }
}
