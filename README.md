# Rakesh Mens Wear

Clothing shop with separate customer and admin logins, admin-only product management, and a live dashboard
that tracks logins, who is online, orders and stock.

The storefront includes product search, category filters, price sorting, size selection, discounts, a shopping bag,
and a delivery phone/address at checkout. Admins can add, edit, hide or remove products and see delivery details on
recent orders. Orders are stored in the shop database and are paid at the store or cash on delivery.

## Run it (Windows / Mac / Linux)
```
python -m venv venv
venv\Scripts\activate          # Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
flask --app app create-admin   # asks for name, email, password (run twice for admin #2)
python app.py
```
Open http://127.0.0.1:5000

| Page | URL | Who |
|---|---|---|
| Shop | `/` | everyone |
| Customer login / register | `/login`, `/register` | customers |
| Admin login | `/admin/login` | admins only |
| Admin dashboard | `/admin` | admins only |

Run `flask --app app create-admin` twice in the activated environment to create the two private admin accounts.
Choose separate email addresses and strong passwords. No default administrator credentials are installed, and there
is no public admin registration page. A third account will be rejected.

## How the rules are enforced
- **Two admins maximum.** Admins can only be created with `flask create-admin`; the command refuses a third. There is no public admin sign-up.
- **Separate logins.** A customer cannot log in on the admin page and an admin cannot log in on the customer page.
- **Admin-only changes.** Adding, editing (name, category, price, discount %, stock, sizes, photo), hiding and deleting clothes, and the stats API, all re-check the admin role in the database on every request. Customers get a redirect or 403.
- **Live tracking.** Each successful login is stored. Logged-in pages ping every 30 s; "online" means seen in the last 70 s. The dashboard refreshes every 5 s, and the shop page every 8 s.
- **Orders.** Prices (after discount) and stock come from the database, never from the browser. Stock is reduced in one transaction, so it cannot be oversold.
- **Security.** Hashed passwords, CSRF tokens, login rate limit (5 failures / 10 min), HttpOnly cookies, image type check by file header, security headers.

## Tests
`python tests/smoke_test.py` (uses a temporary database).

## Before putting it on the internet
- Set `PRODUCTION=1` and a long random `SECRET_KEY` environment variable, and serve over HTTPS (e.g. gunicorn behind Nginx or a host like Render/PythonAnywhere).
- Browser closure does not log a customer out instantly; "online" simply expires after about 70 s.
- The login rate limit is kept in memory (resets on restart, per process).
- Online payment (Razorpay) is not included. Orders are paid at the store or on delivery.
- The included `python app.py` server is for local use. Deploy behind a production WSGI server with HTTPS before
  accepting orders over the public internet. Add a payment provider and delivery/return policies if you need those
  workflows.
- SQLite is fine for a single shop; back up `shop.db` and `static/uploads/` regularly.
