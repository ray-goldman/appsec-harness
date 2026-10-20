using System.Net.Http;
public class Client {
    public HttpClient Make() {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;
        return new HttpClient(handler);
    }
}
