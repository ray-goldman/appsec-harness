using System.Text.Json;
public class Store {
    public Cart Load(System.IO.Stream s) => JsonSerializer.Deserialize<Cart>(s);
}
public record Cart(string Id);
