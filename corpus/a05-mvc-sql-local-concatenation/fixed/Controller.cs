using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Demo.Data;
namespace Demo.Web {
    public class CatalogController : Controller {
        private readonly CatalogDb _db;
        public CatalogController(CatalogDb db) { _db = db; }
        public IActionResult Search(string q) {
            if (string.IsNullOrEmpty(q)) return RedirectToAction("Index");
            var term = q;
            string sql = "SELECT * FROM Listings WHERE Name = {0}";
            var rows = _db.Listings.FromSqlRaw(sql, term).ToList();
            return View(rows);
        }
    }
}
