using System.Runtime.Serialization.Formatters.Binary;
public class Store {
    public object Load(System.IO.Stream s) { var f = new BinaryFormatter(); return f.Deserialize(s); }
}
