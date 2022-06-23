from flask import Flask, render_template, redirect, url_for, flash,request,abort
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField,SelectField
from wtforms.validators import DataRequired
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
login_manager = LoginManager()
login_manager.init_app(app)
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])

class ProductForm(FlaskForm):
    Product_name = StringField("Product", validators=[DataRequired()])
    Price = StringField("Price", validators=[DataRequired()])
    rating = SelectField("Rating", choices=["⭐", "⭐⭐", "⭐⭐⭐", "⭐⭐⭐⭐", "⭐⭐⭐⭐⭐"],
                         validators=[DataRequired()])
    img=StringField("URL",validators=[DataRequired()])
    Product_detail = StringField("Product_detail", validators=[DataRequired()])
    submit=SubmitField("SUBMIT")

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    cart2=relationship("Cart",back_populates="cart1")


class Product(db.Model):
    __tablename__ = "product"
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.String(100), unique=False)
    Price = db.Column(db.String(100))
    Product_name = db.Column(db.String(100))
    Product_detail=db.Column(db.String(100))
    url = db.Column(db.String(100))

class Cart(db.Model):
    __tablename__ = "cart"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    rating = db.Column(db.String(100), unique=False)
    Price = db.Column(db.String(100))
    Product_name = db.Column(db.String(100))
    Product_detail=db.Column(db.String(100))
    url = db.Column(db.String(100))
    cart1 = relationship("User", back_populates="cart2")

db.create_all()

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function
@app.route("/")
def home():
    return render_template("index.html",current_user=current_user)

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            print(User.query.filter_by(email=form.email.data).first())
            #User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home"))

    return render_template("register.html", form=form)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template("login.html", form=form, )

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_product():
    form = ProductForm()
    if form.validate_on_submit():
        new_Product = Product(
            Product_name=form.Product_name.data,
            Price=form.Price.data,
            rating=form.rating.data,
            url=form.img.data,
            Product_detail=form.Product_detail.data

        )
        db.session.add(new_Product)
        db.session.commit()
        return redirect(url_for("add_new_product"))

    return render_template("add-product.html", form=form, current_user=current_user)

@app.route("/productdetail/<int:product_id>", methods=["GET","POST"])
def productdetail(product_id):
    requested_product = Product.query.get(product_id)
    product = Product.query.all()
    return render_template("product-detail.html", curr_product=requested_product,  current_user=current_user,Products=product)

@app.route("/cart/<int:product_id>", methods=["GET","POST"])
def cart(product_id):
    requested_product = Product.query.get(product_id)

    new_Product = Cart(
            Product_name=requested_product.Product_name,
            Price=requested_product.Price,
            rating=requested_product.rating,
            url=requested_product.url,
            Product_detail=requested_product.Product_detail

        )
    db.session.add(new_Product)
    db.session.commit()
    product = Cart.query.all()

    return render_template("cart.html", curr_product=requested_product,  current_user=current_user,Products=product)


@app.route("/product")
def product():
    product=Product.query.all()
    print(product[0].url)
    return render_template("product.html",Products=product)


if __name__ == "__main__":
    app.run(debug=True)
