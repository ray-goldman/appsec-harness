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
            var rows = _db.Listings.FromSql($"SELECT * FROM Listings WHERE Name = {q}").ToList();
            return View(rows);
        }
        private bool HasSession() { return true; }
    }
}
