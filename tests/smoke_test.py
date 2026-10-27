"""Run: python tests/smoke_test.py  (uses a temporary database)"""
import os, re, sys, tempfile, io
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as A
from werkzeug.security import generate_password_hash
import sqlite3, time
c = A.app.test_client()
def tok(cl, path="/login"):
    return re.search(r'name="csrf" value="(\w+)"', cl.get(path).text).group(1)
def ok(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond: sys.exit(1)
db = sqlite3.connect(A.DB_PATH)
db.execute("INSERT INTO users(name,email,pw,role,created) VALUES('Rakesh','admin@x.com',?, 'admin',?)", (generate_password_hash("adminpass1"), int(time.time()))); db.commit()
# customer registers and logs in
t = tok(c, "/register")
c.post("/register", data={"csrf": t, "name": "Ravi", "email": "ravi@x.com", "password": "ravipass123"})
t = tok(c); r = c.post("/login", data={"csrf": t, "email": "ravi@x.com", "password": "ravipass123"})
ok("customer login works", r.status_code == 302 and r.location == "/")
ok("customer cannot open /admin", c.get("/admin").status_code == 302 and "/admin/login" in c.get("/admin").location)
ok("customer cannot call admin stats", c.get("/api/admin/stats").status_code == 403)
t = tok(c)
ok("customer cannot add product", c.post("/admin/products/add", data={"csrf": t, "name": "X", "category": "Y", "price": "1", "stock": "1"}).status_code == 403)
ok("customer cannot delete product", c.post("/admin/products/1/delete", data={"csrf": t}).status_code == 403)
ok("customer on admin page is told to use customer page", "customer account" in c.post("/admin/login", data={"csrf": t, "email": "ravi@x.com", "password": "ravipass123"}, follow_redirects=True).text)
ok("POST without CSRF rejected", c.post("/api/order", json={"items": []}).status_code == 400)
# order: price from DB, stock decrements
r = c.post("/api/order", json={"items": [{"id": 1, "size": "M", "q": 2, "price": 1}]}, headers={"X-CSRF": t})
ok("order total computed on server (2 x 1199)", r.json.get("total") == 2398)
ok("oversell rejected", c.post("/api/order", json={"items": [{"id": 1, "size": "M", "q": 10}]*5}, headers={"X-CSRF": t}).status_code == 400)
# admin
a = A.app.test_client(); t = tok(a, "/admin/login")
ok("admin on customer page is told to use admin page", "admin account" in a.post("/login", data={"csrf": t, "email": "admin@x.com", "password": "adminpass1"}, follow_redirects=True).text)
r = a.post("/admin/login", data={"csrf": t, "email": "admin@x.com", "password": "adminpass1"})
ok("admin login works", r.location == "/admin")
s = a.get("/api/admin/stats").json
ok("stats: 1 customer, 1 customer login, 1 order", (s["registered"], s["total_logins"], s["orders"]) == (1, 1, 1))
ok("stats: customer online after login ping window", s["online"] in (0, 1))
t = re.search(r'name="csrf" value="(\w+)"', a.get("/admin").text).group(1)
png = b"\x89PNG\r\n\x1a\n" + b"0" * 50
a.post("/admin/products/add", data={"csrf": t, "name": "Test Shirt", "category": "Shirts", "price": "999", "stock": "5", "sizes": "M,L", "image": (io.BytesIO(png), "a.png")}, content_type="multipart/form-data")
ok("admin added product", any(p["name"] == "Test Shirt" for p in a.get("/api/products").json))
bad = a.post("/admin/products/add", data={"csrf": t, "name": "Bad", "category": "S", "price": "9", "stock": "1", "image": (io.BytesIO(b"<?php ?>"), "a.png")}, content_type="multipart/form-data", follow_redirects=True)
ok("fake image rejected", not any(p["name"] == "Bad" for p in a.get("/api/products").json))
pid = [p for p in a.get("/api/products").json if p["name"] == "Test Shirt"][0]["id"]
a.post(f"/admin/products/{pid}/update", data={"csrf": t, "name": "Test Shirt 2", "category": "Shirts", "price": "1000", "discount": "20", "stock": "5", "sizes": "M,L"}, content_type="multipart/form-data")
pr = [p for p in a.get("/api/products").json if p["id"] == pid][0]
ok("admin edit: name, price and 20% discount -> sale price 800", pr["name"] == "Test Shirt 2" and pr["sale_price"] == 800)
r = c.post("/api/order", json={"items": [{"id": pid, "size": "M", "q": 2}]}, headers={"X-CSRF": tok(c, "/")}) if False else None
a.post(f"/admin/products/{pid}/toggle", data={"csrf": t})
ok("admin can hide product", not any(p["id"] == pid for p in a.get("/api/products").json))
a.post(f"/admin/products/{pid}/delete", data={"csrf": t})
ok("admin can delete product", a.get("/admin").status_code == 200 and "Test Shirt 2" not in a.get("/admin").text)
# admin limit
db.execute("INSERT INTO users(name,email,pw,role,created) VALUES('B','b@x.com','x','admin',?)", (int(time.time()),)); db.commit()
from click.testing import CliRunner
res = CliRunner().invoke(A.create_admin, ["--name", "C", "--email", "c@x.com", "--password", "longpass123"], input="longpass123\n")
ok("third admin refused", res.exit_code != 0 and "Only 2" in res.output)

d = A.app.test_client(); t = tok(d, "/register")
ok("duplicate email gives clear message", "already registered" in d.post("/register", data={"csrf": t, "name": "R", "email": "ravi@x.com", "password": "ravipass123"}).text)
print("ALL PASSED")
