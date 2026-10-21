using System.IO;
using Microsoft.AspNetCore.Mvc;
class View {
    string Render(string path) {
        var html = File.ReadAllText(path);
        return Html.Raw(html).ToString();
    }
}
