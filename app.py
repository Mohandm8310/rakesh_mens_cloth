"""Rakesh Mens Wear - Flask shop with separate customer/admin logins,
admin-only product management and live login tracking."""
import os, secrets, sqlite3, time
from functools import wraps
import click
from flask import (Flask, g, request, session, redirect, url_for,
                   render_template, jsonify, abort, flash)
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "shop.db"))
UPLOADS = os.path.join(BASE, "static", "uploads")
os.makedirs(UPLOADS, exist_ok=True)
MAX_ADMINS = 2          # hard limit on admin accounts
ONLINE_SECONDS = 70     # "online" = heartbeat within this window

app = Flask(__name__)
_kf = os.path.join(BASE, ".secret_key")
if not os.path.exists(_kf):
    with open(_kf, "w") as f:
        f.write(secrets.token_hex(32))
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or open(_kf).read(),
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("PRODUCTION") == "1",
    MAX_CONTENT_LENGTH=3 * 1024 * 1024, PERMANENT_SESSION_LIFETIME=8 * 3600)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL, pw TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN('customer','admin')),
  created INTEGER NOT NULL, last_seen INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS logins(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT NOT NULL,
  category TEXT NOT NULL, price INTEGER NOT NULL CHECK(price>0), discount INTEGER NOT NULL DEFAULT 0, sizes TEXT NOT NULL,
  stock INTEGER NOT NULL CHECK(stock>=0), image TEXT, active INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
  total INTEGER NOT NULL, items TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL);
"""
SEED = [("Classic Oxford Shirt", "Shirts", 1199, 40), ("Slim Fit Chinos", "Trousers", 1499, 30),
        ("Cotton Kurta", "Ethnic", 1299, 25), ("Denim Jacket", "Jackets", 2499, 15),
        ("Polo T-Shirt", "T-Shirts", 699, 60), ("Formal Trousers", "Trousers", 1799, 20)]

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript(SCHEMA)
    if "discount" not in [r[1] for r in c.execute("PRAGMA table_info(products)")]:
        c.execute("ALTER TABLE products ADD COLUMN discount INTEGER NOT NULL DEFAULT 0")  # upgrade old databases
    order_cols = [r[1] for r in c.execute("PRAGMA table_info(orders)")]
    if "phone" not in order_cols:
        c.execute("ALTER TABLE orders ADD COLUMN phone TEXT NOT NULL DEFAULT ''")
    if "address" not in order_cols:
        c.execute("ALTER TABLE orders ADD COLUMN address TEXT NOT NULL DEFAULT ''")
    if not c.execute("SELECT 1 FROM products LIMIT 1").fetchone():
        c.executemany("INSERT INTO products(name,category,price,sizes,stock,created) VALUES(?,?,?,?,?,?)",
                      [(n, cat, p, "S,M,L,XL,XXL", s, int(time.time())) for n, cat, p, s in SEED])
    c.commit(); c.close()

# ---------- security helpers ----------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]

@app.before_request
def csrf_check():
    if request.method == "POST":
        t = request.form.get("csrf") or request.headers.get("X-CSRF") or ""
        if not secrets.compare_digest(t, session.get("csrf", "")):
            abort(400)

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return r

_fails = {}
def blocked(key):
    now = time.time()
    _fails[key] = [t for t in _fails.get(key, []) if now - t < 600]
    return len(_fails[key]) >= 5

def me():
    uid = session.get("uid")
    if not uid:
        return None
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

@app.context_processor
def inject():
    return {"user": me(), "csrf": csrf_token}

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not me():
            return (jsonify(error="login required"), 401) if request.path.startswith("/api") else redirect(url_for("login"))
        return f(*a, **k)
    return w

def admin_required(f):
    """Role is re-read from the database on every request, never trusted from the browser."""
    @wraps(f)
    def w(*a, **k):
        u = me()
        if not u or u["role"] != "admin":
            if request.method == "GET" and not request.path.startswith("/api"):
                return redirect(url_for("admin_login"))
            abort(403)
        return f(*a, **k)
    return w

# ---------- auth: two separate login pages ----------
def do_login(role, template, dest):
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        key = f"{request.remote_addr}|{email}"
        if blocked(key):
            flash("Too many attempts. Please try again in 10 minutes.")
            return render_template(template)
        u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u and u["role"] == role and check_password_hash(u["pw"], pw):
            session.clear(); session["uid"] = u["id"]; session.permanent = True
            now = int(time.time())
            db().execute("INSERT INTO logins(user_id,ts) VALUES(?,?)", (u["id"], now))
            db().execute("UPDATE users SET last_seen=? WHERE id=?", (now, u["id"]))
            db().commit()
            return redirect(dest)
        if u and check_password_hash(u["pw"], pw):   # right password, wrong login page
            flash("This is an admin account. Please use the Admin login page." if u["role"] == "admin"
                  else "This is a customer account. Please use the Customer login page.")
            return render_template(template)
        _fails.setdefault(key, []).append(time.time())
        flash("Invalid email or password.")   # same message for every failure
    return render_template(template)

@app.route("/login", methods=["GET", "POST"])
def login():
    return do_login("customer", "login.html", "/")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    return do_login("admin", "admin_login.html", "/admin")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:60]
        email = request.form.get("email", "").strip().lower()[:120]
        pw = request.form.get("password", "")
        if not name or "@" not in email or len(pw) < 8:
            flash("Enter your name, a valid email and a password of 8+ characters.")
            return render_template("register.html", name=name, email=email)
        else:
            try:
                db().execute("INSERT INTO users(name,email,pw,role,created) VALUES(?,?,?,'customer',?)",
                             (name, email, generate_password_hash(pw), int(time.time())))
                db().commit()
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("This email is already registered. Please log in instead. "
                      "(Admins need a different email for a customer account.)")
                return render_template("register.html", name=name, email=email)
    return render_template("register.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("shop"))

# ---------- customer side ----------
@app.route("/")
def shop():
    return render_template("shop.html")

def sale(p):
    return p["price"] * (100 - p["discount"]) // 100

def product_dict(p):
    return {"id": p["id"], "name": p["name"], "category": p["category"], "price": p["price"],
            "discount": p["discount"], "sale_price": sale(p),
            "sizes": p["sizes"].split(","), "stock": p["stock"],
            "image": url_for("static", filename="uploads/" + p["image"]) if p["image"] else None}

@app.route("/api/products")
def api_products():
    rows = db().execute("SELECT * FROM products WHERE active=1 ORDER BY id DESC").fetchall()
    return jsonify([product_dict(p) for p in rows])

@app.route("/api/ping", methods=["POST"])
@login_required
def ping():
    db().execute("UPDATE users SET last_seen=? WHERE id=?", (int(time.time()), session["uid"]))
    db().commit()
    return jsonify(ok=True)

@app.route("/api/order", methods=["POST"])
@login_required
def order():
    data = request.get_json(silent=True) or {}
    items = data.get("items")
    if not isinstance(items, list) or not 0 < len(items) <= 30:
        return jsonify(error="Cart is empty."), 400
    phone = "".join(c for c in str(data.get("phone", "")) if c.isdigit())
    address = " ".join(str(data.get("address", "")).split())[:250]
    if not 7 <= len(phone) <= 15 or len(address) < 10:
        return jsonify(error="Enter a valid phone number and delivery address."), 400
    d = db(); total = 0; lines = []
    try:
        d.execute("BEGIN IMMEDIATE")
        for it in items:
            try:
                pid, q, size = int(it["id"]), int(it["q"]), str(it["size"])
            except (KeyError, ValueError, TypeError):
                raise ValueError("Invalid item.")
            p = d.execute("SELECT * FROM products WHERE id=? AND active=1", (pid,)).fetchone()
            if not p or not 1 <= q <= 10 or size not in p["sizes"].split(","):
                raise ValueError("An item is unavailable.")
            cur = d.execute("UPDATE products SET stock=stock-? WHERE id=? AND stock>=?", (q, pid, q))
            if cur.rowcount != 1:
                raise ValueError(f"Not enough stock for {p['name']}.")
            total += sale(p) * q            # price always comes from the database
            lines.append(f"{p['name']} ({size}) x{q}")
        d.execute("INSERT INTO orders(user_id,total,items,phone,address,ts) VALUES(?,?,?,?,?,?)",
                  (session["uid"], total, ", ".join(lines), phone, address, int(time.time())))
        d.commit()
    except ValueError as e:
        d.rollback()
        return jsonify(error=str(e)), 400
    return jsonify(ok=True, total=total)

# ---------- admin side (every route is admin_required) ----------
@app.route("/admin")
@admin_required
def admin():
    products = db().execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    return render_template("admin.html", products=products)

@app.route("/api/admin/stats")
@admin_required
def stats():
    d = db(); now = int(time.time()); cut = now - ONLINE_SECONDS
    one = lambda q, a=(): d.execute(q, a).fetchone()[0]
    customers = d.execute("""SELECT u.name,u.email,u.last_seen,
        (SELECT COUNT(*) FROM logins l WHERE l.user_id=u.id) AS n FROM users u
        WHERE u.role='customer' ORDER BY u.last_seen DESC LIMIT 100""").fetchall()
    logins = d.execute("""SELECT u.name,u.role,l.ts FROM logins l JOIN users u ON u.id=l.user_id
        ORDER BY l.id DESC LIMIT 10""").fetchall()
    orders = d.execute("""SELECT u.name,o.total,o.items,o.phone,o.address,o.ts FROM orders o JOIN users u ON u.id=o.user_id
        ORDER BY o.id DESC LIMIT 10""").fetchall()
    return jsonify(
        now=now, registered=one("SELECT COUNT(*) FROM users WHERE role='customer'"),
        total_logins=one("SELECT COUNT(*) FROM logins l JOIN users u ON u.id=l.user_id WHERE u.role='customer'"),
        online=one("SELECT COUNT(*) FROM users WHERE role='customer' AND last_seen>?", (cut,)),
        orders=one("SELECT COUNT(*) FROM orders"), revenue=one("SELECT COALESCE(SUM(total),0) FROM orders"),
        low_stock=one("SELECT COUNT(*) FROM products WHERE stock<=5 AND active=1"),
        customers=[dict(c, online=c["last_seen"] > cut) for c in customers],
        logins=[dict(x) for x in logins], recent_orders=[dict(o) for o in orders])

def save_image(f):
    if not f or not f.filename:
        return None
    head = f.stream.read(12); f.stream.seek(0)
    if head.startswith(b"\x89PNG"): ext = "png"
    elif head.startswith(b"\xff\xd8\xff"): ext = "jpg"
    elif head[:4] == b"RIFF" and head[8:12] == b"WEBP": ext = "webp"
    else: raise ValueError("Image must be PNG, JPG or WEBP.")
    name = secrets.token_hex(12) + "." + ext
    f.save(os.path.join(UPLOADS, name))
    return name

@app.route("/admin/products/add", methods=["POST"])
@admin_required
def add_product():
    try:
        name = request.form["name"].strip()[:80]
        cat = request.form["category"].strip()[:40]
        price, stock = int(request.form["price"]), int(request.form["stock"])
        discount = int(request.form.get("discount") or 0)
        sizes = ",".join(s.strip().upper() for s in request.form.get("sizes", "S,M,L,XL").split(",") if s.strip())[:40]
        if not name or not cat or not sizes or price <= 0 or stock < 0 or not 0 <= discount <= 90:
            raise ValueError("Please fill all fields with valid values.")
        image = save_image(request.files.get("image"))
        db().execute("INSERT INTO products(name,category,price,discount,sizes,stock,image,created) VALUES(?,?,?,?,?,?,?,?)",
                     (name, cat, price, discount, sizes, stock, image, int(time.time())))
        db().commit(); flash("Product added.")
    except (KeyError, ValueError) as e:
        flash(str(e) if isinstance(e, ValueError) and str(e) else "Invalid product details.")
    return redirect(url_for("admin"))

@app.route("/admin/products/<int:pid>/update", methods=["POST"])
@admin_required
def update_product(pid):
    old = db().execute("SELECT image FROM products WHERE id=?", (pid,)).fetchone()
    if not old:
        abort(404)
    try:
        name = request.form["name"].strip()[:80]
        cat = request.form["category"].strip()[:40]
        price, stock = int(request.form["price"]), int(request.form["stock"])
        discount = int(request.form.get("discount") or 0)
        sizes = ",".join(x.strip().upper() for x in request.form["sizes"].split(",") if x.strip())[:40]
        if not name or not cat or not sizes or price <= 0 or stock < 0 or not 0 <= discount <= 90:
            raise ValueError("Invalid product details.")
        image = save_image(request.files.get("image")) or old["image"]
        db().execute("UPDATE products SET name=?,category=?,price=?,discount=?,sizes=?,stock=?,image=? WHERE id=?",
                     (name, cat, price, discount, sizes, stock, image, pid))
        db().commit()
        if image != old["image"] and old["image"]:
            try: os.remove(os.path.join(UPLOADS, old["image"]))
            except OSError: pass
        flash("Product updated.")
    except (KeyError, ValueError) as e:
        flash(str(e) if isinstance(e, ValueError) and str(e) else "Invalid product details.")
    return redirect(url_for("admin"))

@app.route("/admin/products/<int:pid>/toggle", methods=["POST"])
@admin_required
def toggle_product(pid):
    db().execute("UPDATE products SET active=1-active WHERE id=?", (pid,)); db().commit()
    return redirect(url_for("admin"))

@app.route("/admin/products/<int:pid>/delete", methods=["POST"])
@admin_required
def delete_product(pid):
    p = db().execute("SELECT image FROM products WHERE id=?", (pid,)).fetchone()
    if p:
        db().execute("DELETE FROM products WHERE id=?", (pid,)); db().commit()
        if p["image"]:
            try: os.remove(os.path.join(UPLOADS, p["image"]))
            except OSError: pass
        flash("Product deleted.")
    return redirect(url_for("admin"))

# ---------- CLI: the only way to create admins ----------
@app.cli.command("create-admin")
@click.option("--name", prompt=True)
@click.option("--email", prompt=True)
@click.password_option()
def create_admin(name, email, password):
    c = sqlite3.connect(DB_PATH)
    if c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] >= MAX_ADMINS:
        raise click.ClickException(f"Only {MAX_ADMINS} admin accounts are allowed.")
    if len(password) < 8:
        raise click.ClickException("Password must be at least 8 characters.")
    try:
        c.execute("INSERT INTO users(name,email,pw,role,created) VALUES(?,?,?,'admin',?)",
                  (name, email.strip().lower(), generate_password_hash(password), int(time.time())))
        c.commit()
    except sqlite3.IntegrityError:
        raise click.ClickException("That email is already registered.")
    click.echo("Admin created. Log in at /admin/login")

init_db()
if __name__ == "__main__":
    app.run(debug=False, port=5000)
