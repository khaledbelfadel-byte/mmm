from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import secrets
import os
import re
import hmac

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(64),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=1800
)

DATABASE = "database.db"


print("DATABASE:", os.path.abspath(DATABASE))


def get_db():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection



def init_db():
    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT UNIQUE,
            phone TEXT UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    columns = connection.execute("PRAGMA table_info(users)").fetchall()
    column_names = [column["name"] for column in columns]

    if "email" not in column_names:
        connection.execute("ALTER TABLE users ADD COLUMN email TEXT")

    if "phone" not in column_names:
        connection.execute("ALTER TABLE users ADD COLUMN phone TEXT")

    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)"
    )

    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone)"
    )

    connection.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            price REAL NOT NULL CHECK(price >= 0),
            image TEXT DEFAULT '',
            stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1 CHECK(quantity > 0),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, product_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        )
    """)



    products = [
    ("كراب جوليا", "نوعية ممتازة", 310, 100),
    ("كراب مازيراتي", "نوعية ممتازة", 350, 100),
    ("كراب مازيراتي بالحجر", "نوعية ممتازة", 450, 100),
    ("لولان NR*", "نوعية ممتازة", 310, 100),
    ("لولان NR بالحجر", "نوعية ممتازة", 380, 100),
    ("لولان لوريكس", "نوعية ممتازة", 2000, 100),
    ("كراب بلازمة", "نوعية ممتازة", 340, 100),
    ("حرير عباية", "نوعية ممتازة", 620, 100),
    ("كراب فولار", "نوعية ممتازة", 220, 100),
    ("فيبران بالحجر", "نوعية ممتازة", 360, 100),
    ("فيبران ديجيتال", "نوعية ممتازة", 320, 100),
    ("فيبران أوروبي", "نوعية ممتازة",  280,  100),
    ("لولان كراش", "نوعية ممتازة", 420, 100)
    ]
    
    for name, description, price, stock in products:
        exists = connection.execute(
            "SELECT id FROM products WHERE name = ? AND price = ? LIMIT 1",
            (name, price)
        ).fetchone()

        if not exists:
            connection.execute(
                """
                INSERT INTO products (name, description, price, stock)
                VALUES (?, ?, ?, ?)
                """,
                (name, description, price, stock)
            )

    connection.commit()
    connection.close()


def generate_csrf_token():
    token = session.get("_csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token

    return token


@app.context_processor
def security_context():
    return {
        "csrf_token": generate_csrf_token()
    }


def validate_csrf():
    session_token = session.get("_csrf_token")
    form_token = request.form.get("csrf_token")

    if not session_token or not form_token:
        abort(400)

    if not hmac.compare_digest(session_token, form_token):
        abort(400)


def login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return decorated_function


def clean_text(value, maximum=255):
    if not value:
        return ""

    return value.strip()[:maximum]


def valid_email(email):
    return bool(
        re.fullmatch(
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
            email
        )
    )


def valid_phone(phone):
    return bool(
        re.fullmatch(
            r"^\+?[0-9]{8,15}$",
            phone
        )
    )


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about")
@login_required
def about():
    return render_template("about.html")

@app.route("/contact")
@login_required
def contact():
    return render_template("contact.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("products"))

    if request.method == "POST":
        validate_csrf()

        username = clean_text(request.form.get("username"), 50)
        email = clean_text(request.form.get("email"), 150).lower()
        phone = clean_text(request.form.get("phone"), 20)
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not phone or not password or not confirm_password:
            flash("يرجى ملء جميع الحقول.")
            return redirect(url_for("register"))

        if len(username) < 3:
            flash("اسم المستخدم يجب أن يحتوي على 3 أحرف على الأقل.")
            return redirect(url_for("register"))

        if not valid_email(email):
            flash("البريد الإلكتروني غير صحيح.")
            return redirect(url_for("register"))

        if not valid_phone(phone):
            flash("رقم الهاتف غير صحيح.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("كلمة المرور يجب أن تحتوي على 8 أحرف على الأقل.")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("كلمتا المرور غير متطابقتين.")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        connection = get_db()

        try:
            connection.execute(
                """
                INSERT INTO users (username, email, phone, password)
                VALUES (?, ?, ?, ?)
                """,
                (username, email, phone, password_hash)
            )

            connection.commit()

            flash("تم التسجيل بنجاح! يمكنك الآن تسجيل الدخول.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("اسم المستخدم أو البريد الإلكتروني أو الهاتف مستخدم بالفعل.")
            return redirect(url_for("register"))

        finally:
            connection.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("products"))

    if request.method == "POST":
        validate_csrf()

        login_value = clean_text(
            request.form.get("login"),
            150
        )

        password = request.form.get(
            "password",
            ""
        )

        if not login_value or not password:
            flash("يرجى إدخال البريد الإلكتروني أو رقم الهاتف وكلمة المرور.")
            return redirect(url_for("login"))

        connection = get_db()

        try:
            user = connection.execute(
                """
                SELECT id, username, email, phone, password
                FROM users
                WHERE email = ? OR phone = ?
                LIMIT 1
                """,
                (
                    login_value,
                    login_value
                )
            ).fetchone()

        finally:
            connection.close()

        if user and check_password_hash(
            user["password"],
            password
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True

            return redirect(url_for("products"))

        flash("البريد الإلكتروني أو رقم الهاتف أو كلمة المرور غير صحيحة.")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/products")
def products():
    connection = get_db()
    products = connection.execute(
        "SELECT * FROM products ORDER BY id DESC"
    ).fetchall()
    connection.close()

    return render_template("products.html", products=products)

def extract_numeric_price(price_value):
    """دالة ذكية لاستخراج الرقم فقط من السعر حتى لو كان نصاً مثل '280 متر'"""
    if isinstance(price_value, (int, float)):
        return float(price_value)
    if isinstance(price_value, str):
        # استخراج الأرقام فقط باستخدام التعبيرات المنتظمة
        numbers = re.findall(r'\d+', price_value)
        if numbers:
            return float(numbers[0])
    return 0.0

@app.route("/cart")
@login_required
def cart():
    user_id = session["user_id"]

    connection = get_db()

    cart_items = connection.execute(
        """
        SELECT
            cart.id,
            cart.quantity,
            products.name,
            products.description,
            products.price,
            products.image,
            products.stock
        FROM cart
        JOIN products ON products.id = cart.product_id
        WHERE cart.user_id = ?
        ORDER BY cart.id DESC
        """,
        (user_id,)
    ).fetchall()

    connection.close()

    total = sum(
        item["price"] * item["quantity"]
        for item in cart_items
    )

    return render_template(
        "cart.html",
        cart_items=cart_items,
        total=total
    )


@app.route("/cart/add/<int:product_id>", methods=["POST"])
@login_required
def add_to_cart(product_id):
    validate_csrf()

    user_id = session["user_id"]

    connection = get_db()

    try:
        connection.execute("BEGIN IMMEDIATE")

        product = connection.execute(
            """
            SELECT id, stock
            FROM products
            WHERE id = ?
            LIMIT 1
            """,
            (product_id,)
        ).fetchone()

        if not product:
            connection.rollback()
            abort(404)

        if product["stock"] < 1:
            connection.rollback()
            flash("هذا المنتج غير متوفر حالياً")
            return redirect(url_for("products"))

        item = connection.execute(
            """
            SELECT id, quantity
            FROM cart
            WHERE user_id = ?
              AND product_id = ?
            LIMIT 1
            """,
            (
                user_id,
                product_id
            )
        ).fetchone()

        if item:
            new_quantity = item["quantity"] + 1

            if new_quantity > product["stock"]:
                connection.rollback()
                flash("الكمية المطلوبة غير متوفرة")
                return redirect(url_for("products"))

            connection.execute(
                """
                UPDATE cart
                SET quantity = ?
                WHERE id = ?
                """,
                (
                    new_quantity,
                    item["id"]
                )
            )

        else:
            connection.execute(
                """
                INSERT INTO cart
                (user_id, product_id, quantity)
                VALUES (?, ?, 1)
                """,
                (
                    user_id,
                    product_id
                )
            )

        connection.commit()

    except sqlite3.Error as error:
        connection.rollback()
        print(error)
        flash("حدث خطأ أثناء إضافة المنتج")
        return redirect(url_for("products"))

    finally:
        connection.close()

    flash("تمت إضافة المنتج إلى السلة")
    return redirect(url_for("cart"))


@app.route("/cart/increase/<int:cart_id>", methods=["POST"])
@login_required
def increase_cart(cart_id):
    validate_csrf()

    user_id = session["user_id"]

    connection = get_db()

    try:
        connection.execute("BEGIN IMMEDIATE")

        item = connection.execute(
            """
            SELECT
                cart.id,
                cart.quantity,
                products.stock
            FROM cart
            JOIN products ON products.id = cart.product_id
            WHERE cart.id = ?
              AND cart.user_id = ?
            LIMIT 1
            """,
            (
                cart_id,
                user_id
            )
        ).fetchone()

        if not item:
            connection.rollback()
            abort(404)

        if item["quantity"] >= item["stock"]:
            connection.rollback()
            flash("لا توجد كمية إضافية متوفرة")
            return redirect(url_for("cart"))

        connection.execute(
            """
            UPDATE cart
            SET quantity = quantity + 1
            WHERE id = ?
              AND user_id = ?
            """,
            (
                cart_id,
                user_id
            )
        )

        connection.commit()

    except sqlite3.Error:
        connection.rollback()
        flash("حدث خطأ أثناء تحديث السلة")
        return redirect(url_for("cart"))

    finally:
        connection.close()

    return redirect(url_for("cart"))


@app.route("/cart/decrease/<int:cart_id>", methods=["POST"])
def decrease_cart(cart_id):
    validate_csrf()

    user_id = session["user_id"]

    connection = get_db()

    try:
        connection.execute("BEGIN IMMEDIATE")

        item = connection.execute(
            """
            SELECT quantity
            FROM cart
            WHERE id = ?
              AND user_id = ?
            LIMIT 1
            """,
            (
                cart_id,
                user_id
            )
        ).fetchone()

        if not item:
            connection.rollback()
            abort(404)

        if item["quantity"] <= 1:
            connection.execute(
                """
                DELETE FROM cart
                WHERE id = ?
                  AND user_id = ?
                """,
                (
                    cart_id,
                    user_id
                )
            )

        else:
            connection.execute(
                """
                UPDATE cart
                SET quantity = quantity - 1
                WHERE id = ?
                  AND user_id = ?
                """,
                (
                    cart_id,
                    user_id
                )
            )

        connection.commit()

    except sqlite3.Error:
        connection.rollback()
        flash("حدث خطأ أثناء تحديث السلة")
        return redirect(url_for("cart"))

    finally:
        connection.close()

    return redirect(url_for("cart"))


@app.route("/cart/remove/<int:cart_id>", methods=["POST"])
def remove_from_cart(cart_id):
    validate_csrf()

    user_id = session["user_id"]

    connection = get_db()

    try:
        connection.execute(
            """
            DELETE FROM cart
            WHERE id = ?
              AND user_id = ?
            """,
            (
                cart_id,
                user_id
            )
        )

        connection.commit()

    except sqlite3.Error:
        connection.rollback()
        flash("حدث خطأ أثناء حذف المنتج")
        return redirect(url_for("cart"))

    finally:
        connection.close()

    flash("تم حذف المنتج من السلة")
    return redirect(url_for("cart"))




from datetime import datetime, timedelta
import time


def ensure_extended_database():
    connection = get_db()
    connection.execute("PRAGMA foreign_keys = ON")

    columns = connection.execute("PRAGMA table_info(users)").fetchall()
    names = [column["name"] for column in columns]
    if "role" not in names:
        connection.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    if "is_active" not in names:
        connection.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")

    connection.execute("""
        CREATE TABLE IF NOT EXISTS addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            address TEXT NOT NULL,
            city TEXT NOT NULL,
            postal_code TEXT DEFAULT '',
            is_default INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            address_id INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            payment_method TEXT NOT NULL DEFAULT 'cash_on_delivery',
            subtotal REAL NOT NULL DEFAULT 0,
            discount REAL NOT NULL DEFAULT 0,
            total REAL NOT NULL DEFAULT 0,
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(address_id) REFERENCES addresses(id) ON DELETE SET NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER,
            product_name TEXT NOT NULL,
            unit_price REAL NOT NULL,
            quantity INTEGER NOT NULL CHECK(quantity > 0),
            line_total REAL NOT NULL,
            FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE SET NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS wishlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, product_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
            comment TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, product_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS coupons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            discount_type TEXT NOT NULL DEFAULT 'percent',
            discount_value REAL NOT NULL CHECK(discount_value >= 0),
            minimum_total REAL NOT NULL DEFAULT 0 CHECK(minimum_total >= 0),
            max_uses INTEGER NOT NULL DEFAULT 0 CHECK(max_uses >= 0),
            used_count INTEGER NOT NULL DEFAULT 0 CHECK(used_count >= 0),
            expires_at TIMESTAMP,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS coupon_uses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            coupon_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            order_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(coupon_id, user_id),
            FOREIGN KEY(coupon_id) REFERENCES coupons(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            target_type TEXT DEFAULT '',
            target_id INTEGER,
            details TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS site_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS product_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS product_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            user_id INTEGER,
            ip_address TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    connection.execute("CREATE INDEX IF NOT EXISTS idx_cart_user ON cart(user_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_order_items_order ON order_items(order_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_reviews_product ON reviews(product_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at)")

    connection.commit()
    connection.close()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    connection = get_db()
    user = connection.execute(
        "SELECT id, username, email, phone, role, is_active FROM users WHERE id = ? LIMIT 1",
        (user_id,)
    ).fetchone()
    connection.close()
    return user


def admin_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if not user["is_active"]:
            session.clear()
            flash("الحساب غير مفعل.")
            return redirect(url_for("login"))
        if user["role"] != "admin":
            return "غير مصرح لك بالدخول إلى لوحة الإدارة.", 403
        return function(*args, **kwargs)
    return decorated_function


def write_audit(action, target_type="", target_id=None, details=""):
    connection = get_db()
    connection.execute(
        """
        INSERT INTO audit_logs
        (user_id, action, target_type, target_id, details, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            session.get("user_id"),
            clean_text(action, 100),
            clean_text(target_type, 100),
            target_id,
            clean_text(details, 1000),
            request.remote_addr or ""
        )
    )
    connection.commit()
    connection.close()


def add_notification(user_id, title, message):
    connection = get_db()
    connection.execute(
        "INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)",
        (user_id, clean_text(title, 150), clean_text(message, 1000))
    )
    connection.commit()
    connection.close()


def calculate_coupon(connection, code, user_id, subtotal):
    if not code:
        return None, 0, ""
    coupon = connection.execute(
        """
        SELECT id, code, discount_type, discount_value, minimum_total,
               max_uses, used_count, expires_at, active
        FROM coupons
        WHERE code = ?
        LIMIT 1
        """,
        (code.strip().upper(),)
    ).fetchone()
    if not coupon:
        return None, 0, "رمز الخصم غير صحيح."
    if not coupon["active"]:
        return None, 0, "رمز الخصم غير فعال."
    if coupon["expires_at"]:
        try:
            expires = datetime.fromisoformat(coupon["expires_at"])
            if datetime.now() > expires:
                return None, 0, "رمز الخصم منتهي الصلاحية."
        except ValueError:
            pass
    if coupon["max_uses"] > 0 and coupon["used_count"] >= coupon["max_uses"]:
        return None, 0, "تم استنفاد استخدامات رمز الخصم."
    used = connection.execute(
        "SELECT id FROM coupon_uses WHERE coupon_id = ? AND user_id = ? LIMIT 1",
        (coupon["id"], user_id)
    ).fetchone()
    if used:
        return None, 0, "لقد استخدمت هذا الرمز من قبل."
    if subtotal < coupon["minimum_total"]:
        return None, 0, f"الحد الأدنى لهذا الرمز هو {coupon['minimum_total']:.0f} دج."
    if coupon["discount_type"] == "fixed":
        discount = min(float(coupon["discount_value"]), float(subtotal))
    else:
        discount = min(float(subtotal), float(subtotal) * float(coupon["discount_value"]) / 100)
    return coupon, round(discount, 2), ""


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    validate_csrf()
    user_id = session.get("user_id")
    write_audit("logout")
    session.clear()
    flash("تم تسجيل الخروج.")
    return redirect(url_for("home"))


@app.route("/search")
def search_products():
    query = clean_text(request.args.get("q"), 100)
    min_price = request.args.get("min_price", "")
    max_price = request.args.get("max_price", "")
    connection = get_db()
    sql = "SELECT id, name, description, price, image, stock FROM products WHERE 1=1"
    params = []
    if query:
        sql += " AND (name LIKE ? OR description LIKE ?)"
        value = f"%{query}%"
        params.extend([value, value])
    try:
        if min_price:
            sql += " AND price >= ?"
            params.append(max(0, float(min_price)))
        if max_price:
            sql += " AND price <= ?"
            params.append(max(0, float(max_price)))
    except ValueError:
        pass
    sql += " ORDER BY id DESC LIMIT 100"
    products = connection.execute(sql, params).fetchall()
    connection.close()
    return render_template("products.html", products=products, search_query=query)


@app.route("/product/<int:product_id>")
def product_details(product_id):
    connection = get_db()
    product = connection.execute(
        "SELECT id, name, description, price, image, stock FROM products WHERE id = ? LIMIT 1",
        (product_id,)
    ).fetchone()
    if not product:
        connection.close()
        abort(404)
    connection.execute(
        "INSERT INTO product_views (product_id, user_id, ip_address) VALUES (?, ?, ?)",
        (product_id, session.get("user_id"), request.remote_addr or "")
    )
    reviews = connection.execute(
        """
        SELECT reviews.id, reviews.rating, reviews.comment, reviews.created_at,
               users.username
        FROM reviews
        JOIN users ON users.id = reviews.user_id
        WHERE reviews.product_id = ?
        ORDER BY reviews.id DESC
        """,
        (product_id,)
    ).fetchall()
    average = connection.execute(
        "SELECT AVG(rating) AS average, COUNT(*) AS count FROM reviews WHERE product_id = ?",
        (product_id,)
    ).fetchone()
    connection.commit()
    connection.close()
    return render_template(
        "product.html",
        product=product,
        reviews=reviews,
        average_rating=average["average"] or 0,
        review_count=average["count"]
    )


@app.route("/wishlist")
@login_required
def wishlist_page():
    user_id = session["user_id"]
    connection = get_db()
    items = connection.execute(
        """
        SELECT wishlist.id, products.id AS product_id, products.name,
               products.description, products.price, products.image, products.stock
        FROM wishlist
        JOIN products ON products.id = wishlist.product_id
        WHERE wishlist.user_id = ?
        ORDER BY wishlist.id DESC
        """,
        (user_id,)
    ).fetchall()
    connection.close()
    return render_template("wishlist.html", items=items)


@app.route("/wishlist/toggle/<int:product_id>", methods=["POST"])
@login_required
def wishlist_toggle(product_id):
    validate_csrf()
    user_id = session["user_id"]
    connection = get_db()
    product = connection.execute("SELECT id FROM products WHERE id = ?", (product_id,)).fetchone()
    if not product:
        connection.close()
        abort(404)
    item = connection.execute(
        "SELECT id FROM wishlist WHERE user_id = ? AND product_id = ?",
        (user_id, product_id)
    ).fetchone()
    if item:
        connection.execute("DELETE FROM wishlist WHERE id = ?", (item["id"],))
        message = "تم حذف المنتج من المفضلة."
    else:
        connection.execute(
            "INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)",
            (user_id, product_id)
        )
        message = "تمت إضافة المنتج إلى المفضلة."
    connection.commit()
    connection.close()
    return redirect(request.referrer or url_for("products"))


@app.route("/addresses", methods=["GET", "POST"])
@login_required
def addresses():
    user_id = session["user_id"]
    if request.method == "POST":
        validate_csrf()
        full_name = clean_text(request.form.get("full_name"), 100)
        phone = clean_text(request.form.get("phone"), 20)
        address = clean_text(request.form.get("address"), 300)
        city = clean_text(request.form.get("city"), 100)
        postal_code = clean_text(request.form.get("postal_code"), 20)
        if not full_name or not phone or not address or not city:
            flash("يرجى ملء بيانات العنوان.")
            return redirect(url_for("addresses"))
        connection = get_db()
        connection.execute(
            "INSERT INTO addresses (user_id, full_name, phone, address, city, postal_code) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, full_name, phone, address, city, postal_code)
        )
        connection.commit()
        connection.close()
        flash("تم حفظ العنوان.")
        return redirect(url_for("addresses"))
    connection = get_db()
    items = connection.execute(
        "SELECT * FROM addresses WHERE user_id = ? ORDER BY is_default DESC, id DESC",
        (user_id,)
    ).fetchall()
    connection.close()
    return render_template("addresses.html", addresses=items)


@app.route("/addresses/delete/<int:address_id>", methods=["POST"])
@login_required
def delete_address(address_id):
    validate_csrf()
    connection = get_db()
    connection.execute(
        "DELETE FROM addresses WHERE id = ? AND user_id = ?",
        (address_id, session["user_id"])
    )
    connection.commit()
    connection.close()
    return redirect(url_for("addresses"))


@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    user_id = session["user_id"]
    connection = get_db()
    items = connection.execute(
        """
        SELECT cart.id AS cart_id, cart.quantity, products.id AS product_id,
               products.name, products.price, products.stock
        FROM cart
        JOIN products ON products.id = cart.product_id
        WHERE cart.user_id = ?
        ORDER BY cart.id
        """,
        (user_id,)
    ).fetchall()
    addresses_data = connection.execute(
        "SELECT * FROM addresses WHERE user_id = ? ORDER BY is_default DESC, id DESC",
        (user_id,)
    ).fetchall()
    subtotal = sum(float(item["price"]) * item["quantity"] for item in items)
    if not items:
        connection.close()
        flash("السلة فارغة.")
        return redirect(url_for("products"))
    if request.method == "POST":
        validate_csrf()
        address_id = request.form.get("address_id", type=int)
        payment_method = clean_text(request.form.get("payment_method"), 50)
        notes = clean_text(request.form.get("notes"), 500)
        coupon_code = clean_text(request.form.get("coupon"), 50).upper()
        if payment_method not in {"cash_on_delivery", "bank_transfer"}:
            payment_method = "cash_on_delivery"
        if not address_id:
            connection.close()
            flash("اختر عنوان التوصيل.")
            return redirect(url_for("checkout"))
        address = connection.execute(
            "SELECT id FROM addresses WHERE id = ? AND user_id = ? LIMIT 1",
            (address_id, user_id)
        ).fetchone()
        if not address:
            connection.close()
            flash("العنوان غير صالح.")
            return redirect(url_for("checkout"))
        coupon, discount, coupon_error = calculate_coupon(connection, coupon_code, user_id, subtotal)
        if coupon_error:
            connection.close()
            flash(coupon_error)
            return redirect(url_for("checkout"))
        total = round(max(0, subtotal - discount), 2)
        try:
            connection.execute("BEGIN IMMEDIATE")
            for item in items:
                product = connection.execute(
                    "SELECT id, name, price, stock FROM products WHERE id = ? LIMIT 1",
                    (item["product_id"],)
                ).fetchone()
                if not product or product["stock"] < item["quantity"]:
                    connection.rollback()
                    connection.close()
                    flash(f"الكمية غير متوفرة للمنتج: {item['name']}")
                    return redirect(url_for("checkout"))
            order_cursor = connection.execute(
                """
                INSERT INTO orders
                (user_id, address_id, status, payment_method, subtotal, discount, total, notes)
                VALUES (?, ?, 'pending', ?, ?, ?, ?, ?)
                """,
                (user_id, address_id, payment_method, subtotal, discount, total, notes)
            )
            order_id = order_cursor.lastrowid
            for item in items:
                connection.execute(
                    """
                    INSERT INTO order_items
                    (order_id, product_id, product_name, unit_price, quantity, line_total)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        order_id,
                        item["product_id"],
                        item["name"],
                        item["price"],
                        item["quantity"],
                        round(float(item["price"]) * item["quantity"], 2)
                    )
                )
                connection.execute(
                    "UPDATE products SET stock = stock - ? WHERE id = ?",
                    (item["quantity"], item["product_id"])
                )
            connection.execute("DELETE FROM cart WHERE user_id = ?", (user_id,))
            if coupon:
                connection.execute(
                    "INSERT INTO coupon_uses (coupon_id, user_id, order_id) VALUES (?, ?, ?)",
                    (coupon["id"], user_id, order_id)
                )
                connection.execute(
                    "UPDATE coupons SET used_count = used_count + 1 WHERE id = ?",
                    (coupon["id"],)
                )
            connection.commit()
        except sqlite3.Error:
            connection.rollback()
            connection.close()
            flash("تعذر إنشاء الطلب.")
            return redirect(url_for("checkout"))
        connection.close()
        add_notification(user_id, "تم إنشاء الطلب", f"تم إنشاء طلبك رقم {order_id} بنجاح.")
        write_audit("create_order", "order", order_id, f"total={total}")
        return redirect(url_for("order_details", order_id=order_id))
    connection.close()
    return render_template("checkout.html", items=items, addresses=addresses_data, subtotal=subtotal)


@app.route("/orders")
@login_required
def orders_page():
    connection = get_db()
    orders_data = connection.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],)
    ).fetchall()
    connection.close()
    return render_template("orders.html", orders=orders_data)


@app.route("/order/<int:order_id>")
@login_required
def order_details(order_id):
    connection = get_db()
    order = connection.execute(
        "SELECT * FROM orders WHERE id = ? AND user_id = ? LIMIT 1",
        (order_id, session["user_id"])
    ).fetchone()
    if not order:
        connection.close()
        abort(404)
    items = connection.execute(
        "SELECT * FROM order_items WHERE order_id = ? ORDER BY id",
        (order_id,)
    ).fetchall()
    address = None
    if order["address_id"]:
        address = connection.execute(
            "SELECT * FROM addresses WHERE id = ? LIMIT 1",
            (order["address_id"],)
        ).fetchone()
    connection.close()
    return render_template("order.html", order=order, items=items, address=address)


@app.route("/order/<int:order_id>/cancel", methods=["POST"])
@login_required
def cancel_order(order_id):
    validate_csrf()
    user_id = session["user_id"]
    connection = get_db()
    try:
        connection.execute("BEGIN IMMEDIATE")
        order = connection.execute(
            "SELECT id, status FROM orders WHERE id = ? AND user_id = ? LIMIT 1",
            (order_id, user_id)
        ).fetchone()
        if not order:
            connection.rollback()
            connection.close()
            abort(404)
        if order["status"] not in {"pending", "confirmed"}:
            connection.rollback()
            connection.close()
            flash("لا يمكن إلغاء هذا الطلب الآن.")
            return redirect(url_for("order_details", order_id=order_id))
        items = connection.execute(
            "SELECT product_id, quantity FROM order_items WHERE order_id = ?",
            (order_id,)
        ).fetchall()
        for item in items:
            if item["product_id"]:
                connection.execute(
                    "UPDATE products SET stock = stock + ? WHERE id = ?",
                    (item["quantity"], item["product_id"])
                )
        connection.execute(
            "UPDATE orders SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (order_id,)
        )
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        connection.close()
        flash("تعذر إلغاء الطلب.")
        return redirect(url_for("order_details", order_id=order_id))
    connection.close()
    add_notification(user_id, "تم إلغاء الطلب", f"تم إلغاء الطلب رقم {order_id}.")
    write_audit("cancel_order", "order", order_id)
    return redirect(url_for("order_details", order_id=order_id))


@app.route("/reviews/<int:product_id>", methods=["POST"])
@login_required
def add_review(product_id):
    validate_csrf()
    rating = request.form.get("rating", type=int)
    comment = clean_text(request.form.get("comment"), 1000)
    if rating is None or rating < 1 or rating > 5:
        flash("التقييم يجب أن يكون من 1 إلى 5.")
        return redirect(url_for("product_details", product_id=product_id))
    connection = get_db()
    product = connection.execute("SELECT id FROM products WHERE id = ?", (product_id,)).fetchone()
    if not product:
        connection.close()
        abort(404)
    connection.execute(
        """
        INSERT INTO reviews (user_id, product_id, rating, comment)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id, product_id)
        DO UPDATE SET rating = excluded.rating,
                      comment = excluded.comment,
                      updated_at = CURRENT_TIMESTAMP
        """,
        (session["user_id"], product_id, rating, comment)
    )
    connection.commit()
    connection.close()
    return redirect(url_for("product_details", product_id=product_id))


@app.route("/notifications")
@login_required
def notifications_page():
    connection = get_db()
    items = connection.execute(
        "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 100",
        (session["user_id"],)
    ).fetchall()
    connection.execute(
        "UPDATE notifications SET is_read = 1 WHERE user_id = ?",
        (session["user_id"],)
    )
    connection.commit()
    connection.close()
    return render_template("notifications.html", notifications=items)


@app.route("/coupon/check", methods=["POST"])
@login_required
def coupon_check():
    validate_csrf()
    code = clean_text(request.form.get("code"), 50).upper()
    connection = get_db()
    items = connection.execute(
        """
        SELECT cart.quantity, products.price
        FROM cart JOIN products ON products.id = cart.product_id
        WHERE cart.user_id = ?
        """,
        (session["user_id"],)
    ).fetchall()
    subtotal = sum(float(item["price"]) * item["quantity"] for item in items)
    coupon, discount, error = calculate_coupon(connection, code, session["user_id"], subtotal)
    connection.close()
    if error:
        flash(error)
    else:
        session["coupon_code"] = coupon["code"]
        flash(f"تم تطبيق الخصم: {discount:.0f} دج")
    return redirect(url_for("checkout"))

def admin_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if not user["is_active"]:
            session.clear()
            flash("الحساب غير مفعل.")
            return redirect(url_for("login"))
            
        YOUR_GMAIL = "khaledbelfadel@gmail.com"
        
        if user["email"] != YOUR_GMAIL and user["role"] != "admin":
            return "غير مصرح لك بالدخول إلى لوحة الإدارة.", 403
            
        return function(*args, **kwargs)
    return decorated_function

def admin_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if not user["is_active"]:
            session.clear()
            flash("الحساب غير مفعل.")
            return redirect(url_for("login"))
            
        YOUR_GMAIL = "louaybelattar@gmail.com"
        
        if user["email"] != YOUR_GMAIL and user["role"] != "admin":
            return "غير مصرح لك بالدخول إلى لوحة الإدارة.", 403
            
        return function(*args, **kwargs)
    return decorated_function

@app.route("/admin")
@admin_required
def admin_dashboard():
    connection = get_db()
    stats = {
        "users": connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"],
        "products": connection.execute("SELECT COUNT(*) AS count FROM products").fetchone()["count"],
        "low_stock": connection.execute("SELECT COUNT(*) AS count FROM products WHERE stock <= 5").fetchone()["count"],
        "orders": connection.execute("SELECT COUNT(*) AS count FROM orders").fetchone()["count"],
        "pending": connection.execute("SELECT COUNT(*) AS count FROM orders WHERE status = 'pending'").fetchone()["count"],
        "revenue": connection.execute("SELECT COALESCE(SUM(total), 0) AS total FROM orders WHERE status != 'cancelled'").fetchone()["total"]
    }
    recent_orders = connection.execute("SELECT * FROM orders ORDER BY id DESC LIMIT 20").fetchall()
    connection.close()
    return render_template("admin.html", stats=stats, orders=recent_orders)

@app.route("/admin/products", methods=["GET", "POST"])
@admin_required
def admin_products():
    if request.method == "POST":
        validate_csrf()
        name = clean_text(request.form.get("name"), 150)
        description = clean_text(request.form.get("description"), 500)
        image = clean_text(request.form.get("image"), 500)
        try:
            price = float(request.form.get("price", "0"))
            stock = int(request.form.get("stock", "0"))
        except ValueError:
            flash("السعر أو المخزون غير صالح.")
            return redirect(url_for("admin_products"))
        if not name or price < 0 or stock < 0:
            flash("بيانات المنتج غير صالحة.")
            return redirect(url_for("admin_products"))
        connection = get_db()
        cursor = connection.execute(
            "INSERT INTO products (name, description, price, image, stock) VALUES (?, ?, ?, ?, ?)",
            (name, description, price, image, stock)
        )
        product_id = cursor.lastrowid
        connection.commit()
        connection.close()
        write_audit("create_product", "product", product_id, name)
        flash("تمت إضافة المنتج.")
        return redirect(url_for("admin_products"))
    connection = get_db()
    products_data = connection.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    connection.close()
    return render_template("admin_products.html", products=products_data)


@app.route("/admin/products/<int:product_id>/stock", methods=["POST"])
@admin_required
def admin_update_stock(product_id):
    validate_csrf()
    stock = request.form.get("stock", type=int)
    if stock is None or stock < 0:
        flash("المخزون غير صالح.")
        return redirect(url_for("admin_products"))
    connection = get_db()
    connection.execute("UPDATE products SET stock = ? WHERE id = ?", (stock, product_id))
    connection.commit()
    connection.close()
    write_audit("update_stock", "product", product_id, str(stock))
    return redirect(url_for("admin_products"))


@app.route("/admin/products/<int:product_id>/delete", methods=["POST"])
@admin_required
def admin_delete_product(product_id):
    validate_csrf()
    connection = get_db()
    product = connection.execute("SELECT name FROM products WHERE id = ?", (product_id,)).fetchone()
    if not product:
        connection.close()
        abort(404)
    connection.execute("DELETE FROM products WHERE id = ?", (product_id,))
    connection.commit()
    connection.close()
    write_audit("delete_product", "product", product_id, product["name"])
    return redirect(url_for("admin_products"))


@app.route("/admin/orders")
@admin_required
def admin_orders():
    connection = get_db()
    orders_data = connection.execute(
        """
        SELECT orders.*, users.username, users.email, users.phone
        FROM orders JOIN users ON users.id = orders.user_id
        ORDER BY orders.id DESC
        LIMIT 500
        """
    ).fetchall()
    connection.close()
    return render_template("admin_orders.html", orders=orders_data)


@app.route("/admin/orders/<int:order_id>/status", methods=["POST"])
@admin_required
def admin_order_status(order_id):
    validate_csrf()
    status = clean_text(request.form.get("status"), 30)
    allowed = {"pending", "confirmed", "processing", "shipped", "delivered", "cancelled"}
    if status not in allowed:
        flash("حالة الطلب غير صالحة.")
        return redirect(url_for("admin_orders"))
    connection = get_db()
    order = connection.execute("SELECT user_id, status FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not order:
        connection.close()
        abort(404)
    connection.execute(
        "UPDATE orders SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (status, order_id)
    )
    connection.commit()
    connection.close()
    add_notification(order["user_id"], "تحديث الطلب", f"تم تغيير حالة الطلب رقم {order_id} إلى {status}.")
    write_audit("update_order_status", "order", order_id, status)
    return redirect(url_for("admin_orders"))


@app.route("/admin/users")
@admin_required
def admin_users():
    connection = get_db()
    users_data = connection.execute(
        "SELECT id, username, email, phone, role, is_active, created_at FROM users ORDER BY id DESC"
    ).fetchall()
    connection.close()
    return render_template("admin_users.html", users=users_data)


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def admin_user_role(user_id):
    validate_csrf()
    role = clean_text(request.form.get("role"), 20)
    if role not in {"user", "admin"}:
        return redirect(url_for("admin_users"))
    if user_id == session["user_id"] and role != "admin":
        flash("لا يمكنك إزالة صلاحية الإدارة من حسابك أثناء تسجيل الدخول.")
        return redirect(url_for("admin_users"))
    connection = get_db()
    connection.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    connection.commit()
    connection.close()
    write_audit("change_user_role", "user", user_id, role)
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/active", methods=["POST"])
@admin_required
def admin_user_active(user_id):
    validate_csrf()
    if user_id == session["user_id"]:
        flash("لا يمكنك تعطيل حسابك الحالي.")
        return redirect(url_for("admin_users"))
    connection = get_db()
    connection.execute("UPDATE users SET is_active = CASE is_active WHEN 1 THEN 0 ELSE 1 END WHERE id = ?", (user_id,))
    connection.commit()
    connection.close()
    write_audit("toggle_user_active", "user", user_id)
    return redirect(url_for("admin_users"))


@app.route("/admin/coupons", methods=["GET", "POST"])
@admin_required
def admin_coupons():
    if request.method == "POST":
        validate_csrf()
        code = clean_text(request.form.get("code"), 50).upper()
        discount_type = clean_text(request.form.get("discount_type"), 20)
        try:
            discount_value = float(request.form.get("discount_value", "0"))
            minimum_total = float(request.form.get("minimum_total", "0"))
            max_uses = int(request.form.get("max_uses", "0"))
        except ValueError:
            flash("بيانات الكوبون غير صالحة.")
            return redirect(url_for("admin_coupons"))
        if not code or discount_type not in {"percent", "fixed"} or discount_value < 0 or minimum_total < 0 or max_uses < 0:
            flash("بيانات الكوبون غير صالحة.")
            return redirect(url_for("admin_coupons"))
        expires_at = clean_text(request.form.get("expires_at"), 30) or None
        connection = get_db()
        try:
            connection.execute(
                """
                INSERT INTO coupons
                (code, discount_type, discount_value, minimum_total, max_uses, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (code, discount_type, discount_value, minimum_total, max_uses, expires_at)
            )
            connection.commit()
        except sqlite3.IntegrityError:
            connection.rollback()
            flash("رمز الخصم موجود بالفعل.")
        finally:
            connection.close()
        return redirect(url_for("admin_coupons"))
    connection = get_db()
    coupons_data = connection.execute("SELECT * FROM coupons ORDER BY id DESC").fetchall()
    connection.close()
    return render_template("admin_coupons.html", coupons=coupons_data)


@app.route("/admin/coupons/<int:coupon_id>/toggle", methods=["POST"])
@admin_required
def admin_coupon_toggle(coupon_id):
    validate_csrf()
    connection = get_db()
    connection.execute("UPDATE coupons SET active = CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id = ?", (coupon_id,))
    connection.commit()
    connection.close()
    return redirect(url_for("admin_coupons"))


@app.route("/admin/logs")
@admin_required
def admin_logs():
    connection = get_db()
    logs = connection.execute(
        """
        SELECT audit_logs.*, users.username
        FROM audit_logs LEFT JOIN users ON users.id = audit_logs.user_id
        ORDER BY audit_logs.id DESC LIMIT 500
        """
    ).fetchall()
    connection.close()
    return render_template("admin_logs.html", logs=logs)


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        validate_csrf()
        maintenance = "1" if request.form.get("maintenance") == "1" else "0"
        connection = get_db()
        connection.execute(
            "INSERT INTO site_settings (key, value) VALUES ('maintenance', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (maintenance,)
        )
        connection.commit()
        connection.close()
        write_audit("update_site_settings")
        flash("تم حفظ إعدادات الموقع.")
        return redirect(url_for("admin_settings"))
    connection = get_db()
    settings = connection.execute("SELECT key, value FROM site_settings ORDER BY key").fetchall()
    connection.close()
    return render_template("admin_settings.html", settings=settings)


@app.before_request
def maintenance_guard():
    endpoint = request.endpoint or ""
    allowed = {"static", "login", "register", "home", "admin_settings"}
    if endpoint in allowed or endpoint.startswith("admin_"):
        return None
    connection = get_db()
    setting = connection.execute("SELECT value FROM site_settings WHERE key = 'maintenance' LIMIT 1").fetchone()
    connection.close()
    if setting and setting["value"] == "1":
        user = current_user()
        if not user or user["role"] != "admin":
            return "الموقع تحت الصيانة حاليًا. حاول لاحقًا.", 503
    return None


_original_init_db = init_db


def init_db_complete():
    _original_init_db()
    ensure_extended_database()


init_db = init_db_complete

    init_db ()

if __name__ == "__main__":
    app.run()
