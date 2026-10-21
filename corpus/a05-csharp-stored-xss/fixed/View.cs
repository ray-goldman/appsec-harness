using System.IO;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;
class View {
    string Render(string path) {
        var html = File.ReadAllText(path);
        var safe = HtmlEncoder.Default.Encode(html);
        return Html.Raw(safe).ToString();
    }
}
