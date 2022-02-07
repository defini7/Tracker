import os
from types import new_class

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask.helpers import get_flashed_messages
from flask.json.tag import PassList
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from re import *

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

@app.route("/")
@login_required
def index():
    downloads = db.execute("SELECT price AS Price, link AS Link, user_id AS UserId, title AS Title FROM downloads WHERE user_id = :id", id=session["user_id"])
    return render_template("downloads.html", downloads = downloads)

@app.route("/admin")
@login_required
def admin_panel():
    pass

@app.route("/shop", methods=["GET", "POST"])
@login_required
def shop():
    goods = db.execute("SELECT user_id AS UserId, good_id AS GoodId, title AS Title, price AS Price, add_time AS UploadTime FROM goods")
    if request.method == "GET":
        return render_template("shop.html", goods=goods)
    if request.method == "POST":
        good = request.form.get("buy")
        #try:
        if request.form.get("buy"):
            title = db.execute("SELECT title FROM goods WHERE good_id = :id", id = good)
            link = db.execute("SELECT link FROM goods WHERE good_id = :id", id = good)
            author = db.execute("SELECT username FROM users WHERE id = (SELECT user_id FROM goods WHERE good_id = :id)", id=good)
            author_id = db.execute("SELECT id FROM users WHERE username = :name", name=author[0]["username"])
            money = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
            price = db.execute("SELECT price FROM goods WHERE good_id = :id", id=good)
            if author_id[0]["id"] == session["user_id"]:
                flash("You can't buy your own good!")
            elif money[0]["cash"] < price[0]["price"]:
                tmp = price[0]["price"] - money[0]["cash"]
                flash(f"Not enough money! You need {tmp} more dollars.")
                del tmp
            else:
                money[0]["cash"] -= price[0]["price"]
                db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=money[0]["cash"], id=session["user_id"])
                db.execute("UPDATE goods SET sales = sales + 1 WHERE good_id = :id", id=good)
                db.execute("INSERT INTO downloads (user_id, good_id, title, link, author, price) VALUES(?, ?, ?, ?, ?, ?)", session["user_id"], int(good), title[0]["title"], link[0]["link"], author[0]["username"], price[0]["price"])
            return render_template("shop.html", goods=goods)
        #except Exception:
            #flash(f"Invalid ID: {good}")
    return render_template("shop.html", goods=goods)

@app.route("/mygoods", methods=["POST", "GET"])
@login_required
def mygoods():
    mygoods = db.execute("SELECT good_id AS GoodId, title AS Title, price AS Price, add_time AS UploadTime, link AS Link FROM goods WHERE user_id = :id", id=session["user_id"])
    if request.method == "GET":
        return render_template("my_goods.html", mygoods=mygoods)
    if request.method == "POST":
        name = request.form.get("good_name_toupload")
        price = request.form.get("good_price_toupload")
        link = request.form.get("good_link_toupload")
        good_id = db.execute("SELECT MAX(good_id) FROM goods")
        todeletegoodid = request.form.get("delete_good")
        if request.form.get("delete_good"):
            if todeletegoodid.isnumeric():
                tmp = db.execute("SELECT user_id FROM goods WHERE good_id = :good_id", good_id=todeletegoodid)
                if session["user_id"] == tmp[0]["user_id"]:
                    db.execute("DELETE FROM goods WHERE user_id = :id AND good_id = :good_id", id=session["user_id"], good_id=todeletegoodid)
                    flash(f"Good #{todeletegoodid} was deleted successful")
                    return redirect("/mygoods")
                else:
                    flash("Invalid good ID or it is not your good!")
                del tmp
            else:
                flash("Invalid good ID or it is not your good!")
        else:
            if good_id[0]["MAX(good_id)"] == None:
                goodId = 1
            else:
                goodId = int(good_id[0]["MAX(good_id)"]) + 1
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            db.execute("INSERT INTO goods (user_id, good_id, title, price, link, add_time) VALUES (:user_id, :good_id, :title, :price, :link, :timestamp)", user_id=session["user_id"], good_id=goodId, title=name, price=price, link=link, timestamp=timestamp)
            flash(f"Good #{goodId} was uploaded successful. ")
            return redirect("/mygoods")
        return render_template("my_goods.html", mygoods=mygoods)
    return redirect("/mygoods")

@app.route("/addmoney", methods=["POST", "GET"])
@login_required
def addmoney():
    if request.method == "GET":
        return render_template("add_money.html")
    if request.method == "POST":
        flash("Wait ~2 days and check your balance")
    return render_template("add_money.html")

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    profile_name = db.execute("SELECT username FROM users WHERE id = :id", id=session["user_id"])
    balance = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
    if request.method == "GET":
        return render_template("profile.html", profile_name=profile_name[0]["username"], balance=balance)
    if request.method == "POST":
        return render_template("profile.html", profile_name=profile_name[0]["username"], balance=balance)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("Invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        pattern = compile('(^|\s)[-a-z0-9_.]+@([-a-z0-9]+\.)+[a-z]{2,6}(\s|$)')
        username = request.form.get("username")
        email = request.form.get("email")
        is_valid = pattern.match(email)
        if is_valid:
            pass
        else:
            return apology("Invalid E-Mail adress!", 400)
        if len(db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))) == 0:
            pass1 = request.form.get("password")
            pass2 = request.form.get("confirmation")
            if pass1 != pass2:
                return apology("Password don't match!", 400)
            if not username:
                return apology("Missing username!", 400)
            elif not pass1:
                return apology("Missing password!", 400)
            hashed = generate_password_hash(pass1)
            db.execute("INSERT INTO users (username, email, hash, cash) VALUES(?, ?, ?, ?)", username, email, hashed, 0)
            flash("Registration was successful!")
            return redirect("/")
        else:
            return apology("Please choose another username!", 400)
    return render_template("register.html")

@app.route("/change_pw", methods=["GET", "POST"])
@login_required
def change_pw():
    if request.method == "GET":
        return render_template("change_pw.html")
    if request.method == "POST":
        old_password = request.form.get("old_password")
        hashed = generate_password_hash(old_password)
        old_hashed_password = db.execute("SELECT hash FROM users WHERE id = :id", id=session["user_id"])
        if hashed != old_hashed_password:
            return apology("Old password is wrong", 400)
        if not old_password:
            return apology("Missing old password!", 400)
        pass1 = request.form.get("password")
        pass2 = request.form.get("confirmation")
        if pass1 != pass2:
            return apology("Passwords don't match", 400)
        elif not pass1:
            return apology("Missing new password!", 400)
        elif not pass2:
            return apology("Missing confirmation!", 400)
        hashh = generate_password_hash(pass1)
        db.execute("UPDATE users SET hash = :hash WHERE id=:id", hash=hashh, id=session["user_id"])
        flash("You changed your password successful!")
        return redirect("/")
    return render_template("change_pw.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
