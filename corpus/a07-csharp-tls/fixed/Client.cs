using System.Net.Http;
public class Client {
    public HttpClient Make() => new HttpClient(new HttpClientHandler());
}
