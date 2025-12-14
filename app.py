import os
from datetime import datetime
from typing import Optional

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "marketplace.db")


def create_app():
    """Build the Flask application with explicit template/static locations.

    Using absolute paths prevents Jinja from failing to locate templates when
    the app is launched from a different working directory (a common cause of
    raw `{{ ... }}` blocks being rendered in the browser).
    """
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, "docs"),
        static_folder=os.path.join(BASE_DIR, "static"),
    )
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    return app


def create_login_manager(app: Flask):
    manager = LoginManager()
    manager.login_view = "login"
    manager.login_message_category = "warning"
    manager.init_app(app)
    return manager


app = create_app()
db = SQLAlchemy(app)
login_manager = create_login_manager(app)


class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    can_manage_all_listings = db.Column(db.Boolean, default=False)
    can_manage_roles = db.Column(db.Boolean, default=False)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Role {self.name}>"


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    nickname = db.Column(db.String(80), nullable=False)
    discord = db.Column(db.String(100), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)

    role = db.relationship(Role, backref="users")
    listings = db.relationship(
        "Listing", cascade="all, delete-orphan", backref="owner", lazy=True
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return bool(self.role and self.role.can_manage_roles)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<User {self.username}>"


class Listing(db.Model):
    __tablename__ = "listings"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    contact_discord = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Listing {self.title}>"


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return User.query.get(int(user_id))


@app.before_request
def ensure_defaults():
    db.create_all()
    seed_roles()


@app.context_processor
def inject_now():
    return {"current_year": datetime.utcnow().year}


def seed_roles():
    """Create default roles for a fresh database."""
    if Role.query.count() == 0:
        default_roles = [
            Role(
                name="Учасник",
                description="Базова роль для публікації власних оголошень",
                can_manage_all_listings=False,
                can_manage_roles=False,
            ),
            Role(
                name="Модератор",
                description="Може модерувати всі оголошення",
                can_manage_all_listings=True,
                can_manage_roles=False,
            ),
            Role(
                name="Адміністратор",
                description="Повний доступ до управління ролями та оголошеннями",
                can_manage_all_listings=True,
                can_manage_roles=True,
            ),
        ]
        db.session.add_all(default_roles)
        db.session.commit()


def require_permission(listing: Listing) -> bool:
    if not current_user.is_authenticated:
        return False
    if listing.owner.id == current_user.id:
        return True
    return bool(current_user.role and current_user.role.can_manage_all_listings)


app.jinja_env.globals["require_permission"] = require_permission


@app.route("/")
def index():
    category = request.args.get("category")
    sort = request.args.get("sort", "date_desc")

    listings_query = Listing.query
    if category and category != "all":
        listings_query = listings_query.filter_by(category=category)

    if sort == "price_asc":
        listings_query = listings_query.order_by(Listing.price.asc())
    elif sort == "price_desc":
        listings_query = listings_query.order_by(Listing.price.desc())
    elif sort == "date_asc":
        listings_query = listings_query.order_by(Listing.created_at.asc())
    else:
        listings_query = listings_query.order_by(Listing.created_at.desc())

    listings = listings_query.all()
    categories = [
        "транспорт",
        "нерухомість",
        "одяг",
        "аксесуари",
        "інше",
    ]
    return render_template("index.html", listings=listings, categories=categories)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        nickname = request.form.get("nickname")
        discord = request.form.get("discord")

        if not all([username, password, nickname, discord]):
            flash("Заповніть усі поля", "danger")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Користувач з таким логіном вже існує", "warning")
            return redirect(url_for("register"))

        member_role = Role.query.filter_by(name="Учасник").first()
        user = User(
            username=username,
            nickname=nickname,
            discord=discord,
            role=member_role,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Реєстрація успішна! Увійдіть у свій акаунт.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Ви успішно увійшли!", "success")
            next_page = request.args.get("next") or url_for("index")
            return redirect(next_page)
        flash("Невірний логін або пароль", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Ви вийшли з акаунту", "info")
    return redirect(url_for("index"))


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@app.route("/listings/create", methods=["GET", "POST"])
@login_required
def create_listing():
    categories = [
        "транспорт",
        "нерухомість",
        "одяг",
        "аксесуари",
        "інше",
    ]
    if request.method == "POST":
        title = request.form.get("title")
        category = request.form.get("category")
        price = request.form.get("price")
        description = request.form.get("description")
        contact_discord = request.form.get("contact_discord")

        if not all([title, category, price, description, contact_discord]):
            flash("Заповніть усі поля", "danger")
            return redirect(url_for("create_listing"))

        listing = Listing(
            title=title,
            category=category,
            price=float(price),
            description=description,
            contact_discord=contact_discord,
            owner=current_user,
        )
        db.session.add(listing)
        db.session.commit()
        flash("Оголошення створено!", "success")
        return redirect(url_for("profile"))
    return render_template("create_listing.html", categories=categories)


@app.route("/listings/<int:listing_id>/edit", methods=["GET", "POST"])
@login_required
def edit_listing(listing_id: int):
    listing = Listing.query.get_or_404(listing_id)
    if listing.owner.id != current_user.id:
        flash("Ви можете редагувати лише власні оголошення", "danger")
        return redirect(url_for("profile"))

    categories = [
        "транспорт",
        "нерухомість",
        "одяг",
        "аксесуари",
        "інше",
    ]
    if request.method == "POST":
        listing.title = request.form.get("title")
        listing.category = request.form.get("category")
        listing.price = float(request.form.get("price"))
        listing.description = request.form.get("description")
        listing.contact_discord = request.form.get("contact_discord")
        db.session.commit()
        flash("Оголошення оновлено", "success")
        return redirect(url_for("profile"))
    return render_template(
        "create_listing.html", listing=listing, categories=categories, editing=True
    )


@app.route("/listings/<int:listing_id>/delete", methods=["POST"])
@login_required
def delete_listing(listing_id: int):
    listing = Listing.query.get_or_404(listing_id)
    if not require_permission(listing):
        flash("Ви не можете видаляти це оголошення", "danger")
        return redirect(url_for("index"))
    db.session.delete(listing)
    db.session.commit()
    flash("Оголошення видалено", "info")
    return redirect(request.referrer or url_for("index"))


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin_panel():
    if not current_user.role or not (
        current_user.role.can_manage_all_listings or current_user.role.can_manage_roles
    ):
        flash("Доступ заборонено", "danger")
        return redirect(url_for("index"))

    users = User.query.all()
    roles = Role.query.all()
    listings = Listing.query.order_by(Listing.created_at.desc()).all()
    return render_template("admin.html", users=users, roles=roles, listings=listings)


@app.route("/admin/roles/create", methods=["POST"])
@login_required
def create_role():
    if not current_user.role or not current_user.role.can_manage_roles:
        flash("Недостатньо прав", "danger")
        return redirect(url_for("admin_panel"))

    name = request.form.get("name")
    description = request.form.get("description")
    can_manage_all_listings = bool(request.form.get("can_manage_all_listings"))
    can_manage_roles = bool(request.form.get("can_manage_roles"))

    if not name:
        flash("Назва ролі обов'язкова", "danger")
        return redirect(url_for("admin_panel"))

    if Role.query.filter_by(name=name).first():
        flash("Роль з такою назвою вже існує", "warning")
        return redirect(url_for("admin_panel"))

    role = Role(
        name=name,
        description=description,
        can_manage_all_listings=can_manage_all_listings,
        can_manage_roles=can_manage_roles,
    )
    db.session.add(role)
    db.session.commit()
    flash("Роль створено", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
def assign_role(user_id: int):
    if not current_user.role or not current_user.role.can_manage_roles:
        flash("Недостатньо прав", "danger")
        return redirect(url_for("admin_panel"))

    role_id = request.form.get("role_id")
    user = User.query.get_or_404(user_id)
    role = Role.query.get(role_id)
    if role:
        user.role = role
        db.session.commit()
        flash("Роль оновлено", "success")
    else:
        flash("Роль не знайдено", "danger")
    return redirect(url_for("admin_panel"))


@app.route("/admin/listings/<int:listing_id>/delete", methods=["POST"])
@login_required
def admin_delete_listing(listing_id: int):
    if not current_user.role or not current_user.role.can_manage_all_listings:
        flash("Недостатньо прав", "danger")
        return redirect(url_for("admin_panel"))
    listing = Listing.query.get_or_404(listing_id)
    db.session.delete(listing)
    db.session.commit()
    flash("Оголошення видалено модерацією", "info")
    return redirect(url_for("admin_panel"))


@app.errorhandler(404)
def page_not_found(_):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
