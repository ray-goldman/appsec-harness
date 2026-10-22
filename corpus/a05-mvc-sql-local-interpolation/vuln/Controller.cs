using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Demo.Data;
namespace Demo.Web {
    public class CatalogController : Controller {
        private readonly CatalogDb _db;
        public CatalogController(CatalogDb db) { _db = db; }
        [HttpGet]
        public IActionResult Search(string q) {
            if (!HasSession()) return RedirectToAction("Index");
            string sql = $"SELECT * FROM Listings WHERE Name LIKE '%{q}%'";
            var rows = _db.Listings.FromSqlRaw(sql).ToList();
            return View(rows);
        }
        private bool HasSession() { return true; }
    }
}
