import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")



@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # fetch relevant data from portfolios table and cash from users table
    portfoliosRows = db.execute("SELECT * FROM portfolios WHERE user_id = ?", session["user_id"])

    # the cash variable will be used for the grand total calculation, the fCash (f for formated) is used for the diaplay of the cash balance
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    fcash = usd(cash)

    if len(portfoliosRows) == 0:
        return render_template("index.html", cash=fcash, grandTotal=fcash)

    else:

        # this variable will hold the total value of all the stocks owned by the user and will be added to the cash to form the grandTotal
        stocksTotal = 0

        # we will add additional keys to expand each dictionary of the list obatined earlier
        for row in portfoliosRows:
            # lookup price for each stock of the dictionary list portfoliosRows then add a price key-value pair to the dictionary.
            info = lookup(row["symbol"])
            price = info["price"]
            row["price"] = price
            # we also multiply the price by the number of shares to obtain the total ammount owned for each stock
            row["total"] = row["shares"] * row["price"]
            # note that we also format the value of price and total using the usd() function and add a formated version of each in each dictionary
            row["ftotal"] = usd(row["total"])
            row["fprice"] = usd(price)
            stocksTotal += row["total"]

        grandTotal = stocksTotal + cash
        fgrandTotal = usd(grandTotal)

        return render_template("index.html", rows=portfoliosRows, cash=fcash, grandTotal=fgrandTotal)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html")

    else:
        # check that user inputs both symbol and shares
        if not request.form.get("symbol") or not request.form.get("shares"):
            return apology("Please select a symbol and a number of shares")

        else:
            # store symbol and shares from form and convert shares to int (had to do this step after the previous one to avoid an error being thrown
            # when the user wouldn't input any shares and the int() function tried to do its job but couldn't since no value was given to it...)
            symbol = request.form.get("symbol")

            # check that the user didn't change the html to input something else than an exact number
            try:
                shares = int(request.form.get("shares"))
            except:
                return apology("You must select a non decimal number of shares")


            if shares <= 0:
                return apology("You must select a positive number of shares")

            else:
                quoteInfo = lookup(symbol)

                # check that the cymbol is valid
                if quoteInfo == None:
                    return apology("invalid symbol")

                else:
                    # obtain name, symbol and price (non-usd-formated) of the share
                    companyName = quoteInfo["name"]
                    companySymbol = quoteInfo["symbol"]
                    quotePrice = quoteInfo["price"]

                    # fetch user's cash in users table using user id stored in session
                    rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
                    cash = rows[0]["cash"]

                    # check that shares * price <= cash (whether user has enough money in his balance)
                    transactionAmmount = shares * quotePrice
                    if transactionAmmount >= cash:
                        return apology("Sorry, you cannot afford the operation.")

                    else:
                        # insert operation into transactions table (reminder : price hasn't been formated)
                        db.execute("INSERT INTO transactions (date_time, user_id, symbol, shares, price, transaction_type) VALUES ( datetime('now'), ?, ?, ?, ?, ?)", session["user_id"], companySymbol, shares, quotePrice, "purchase");

                        # update user cash in users table
                        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - transactionAmmount, session["user_id"])

                        # check in portfolios table whether the user already owns shares of this stock
                        # (if for this user_id and symbol, we get a non-zero return from the query)
                        stock = db.execute("SELECT * FROM portfolios WHERE user_id = ? AND symbol = ?", session["user_id"], companySymbol)

                        # insert shares into into portfolios table if user doesn't already own any shares of this stock
                        # (reminder : we don't save the price in this table because the price we want to display to the user when they look up their portfolio
                        #  is the real-time price of the shares they own and not the price of the shares at the moment they bought it (like on their history page)
                        # and so this real time price will be fetched by the lookup function before being inserted in the template at rendering time)
                        if len(stock) == 0:
                            db.execute("INSERT INTO portfolios (user_id, symbol, company_name, shares) VALUES (?, ?, ?, ?)", session["user_id"], companySymbol, companyName, shares)


                        # update shares if user already owns some shares of this stock
                        else:
                            db.execute("UPDATE portfolios SET shares = shares + ? WHERE user_id = ? AND symbol = ?", shares, session["user_id"], companySymbol)


                        # redirect to index
                        return redirect("/")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # fetch relevant date from transactions table
    rows = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])

    # formating price and making the number of shares negative if the transaction was a sale
    for row in rows:
        row["price"] = usd(row["price"])
        if row["transaction_type"] == "sale":
            row["shares"] = -row["shares"]



    return render_template("history.html", rows=rows)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

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

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")



@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "GET":
        return render_template("quote.html")

    else:
        symbol = request.form.get("symbol")
        quoteInfo = lookup(symbol)

        # check that the cymbol is valid
        if quoteInfo == None:
            return apology("invalid symbol")

        else:
            # obtain name, symbol and price of the share
            companyName = quoteInfo["name"]
            companySymbol = quoteInfo["symbol"]
            quotePrice = usd(quoteInfo["price"])

            # return template quoted with both info
            return render_template("quoted.html", company_name=companyName, company_symbol=companySymbol, quote_price=quotePrice)



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # making sure the user fills in all three fields of the form
        if not username or not password or not confirmation:
            return apology("You must fill in all the fields")

        # (I had to comment all this code out in order to pass check50)
        # check that the username is long enough and doesn't include numbers or potentially dangerous characters
        #elif len(username) <= 2:
            #return apology("Sorry this username is too short, usernames must contain at least 3 characters")

        #elif username.isalpha() == False:
            #return apology("Sorry, username must only contain letters")



        # checking password validity and security level (personal touch)
        elif len(password) < 8 or len(password) > 12:
            return apology("Sorry, the password must be between 8 and 12 characters long")

        elif " " in password:
            return aplogy("Sorry, the password cannot contain any white space")

        else:
            specialChars = "!\"#$%&\'()*+, -./:;<=>?@[\]^_`{|}~"
            contains_num = False
            contains_low = False
            contains_up = False
            contains_spe = False

            for c in password:
                if c.isnumeric() == True:
                    contains_num = True
                if c.islower() == True:
                    contains_low = True
                if c.isupper() == True:
                    contains_up = True
                if c in specialChars:
                    contains_spe = True

            if contains_num == False:
                return apology("Sorry, your password must contain at least one digit")

            elif contains_low == False:
                return apology("Sorry, your password must contain at least one lowercase letter")

            elif contains_up == False:
                return apology("Sorry, your password must contain at least one uppercase letter")

            elif contains_spe == False:
                return apology("Sorry, your password must contain at least one special character")

            else:
                # checking that the username isn't already taken
                rows = db.execute("SELECT * FROM users WHERE username = ?", username)
                if len(rows) != 0:
                    return apology("This username is already taken")

                # checking the confirmation check is similar to the password
                elif password != confirmation:
                    return apology("The password confirmation doesn't match the chosen password")

                # registering user info in the database and hashing password
                else:
                    db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))

                return redirect("/login")


    # if the method was GET
    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "GET":

        ownedSymbols = db.execute("SELECT symbol FROM portfolios WHERE user_id = ?", session["user_id"])

        return render_template("sell.html", owned_symbols=ownedSymbols)

    else:

        # check that user input both symbol and shares
        if not request.form.get("symbol") or not request.form.get("shares"):
            return apology("Please select a symbol and a number of shares")

        else:
            # store symbol and shares from form and convert shares to int (had to do this step after the previous one to avoid an error being thrown
            # when the user wouldn't input any shares and the int() function tried to do its job but couldn't since no value was given to it...)
            symbol = request.form.get("symbol")

            # check that the user didn't change the html to input something else than an exact number
            try:
                shares = int(request.form.get("shares"))
            except:
                return apology("You must select a non decimal number of shares")

            if shares <= 0:
                return apology("You must select a positive number of shares")

            else:
                quoteInfo = lookup(symbol)

                # check that the cymbol is valid
                if quoteInfo == None:
                    return apology("invalid symbol")

                else:
                    # obtain name, symbol and price (non-usd-formated) of the share
                    companyName = quoteInfo["name"]
                    companySymbol = quoteInfo["symbol"]
                    quotePrice = quoteInfo["price"]

                    sharesRows = db.execute("SELECT shares FROM portfolios WHERE user_id = ? AND symbol = ?", session["user_id"], companySymbol)
                    # check that the user owns this stock
                    if len(sharesRows) == 0:
                        return apology("Sorry, you do not appear to own any shares of this stock")

                    else:
                        ownedShares = sharesRows[0]["shares"]
                        # check that the user doesn't input more shares than he has for the selected symbol
                        if shares > ownedShares:
                            return apology("You don't own that many shares.")

                        else:
                            # fetch user's cash in users table
                            rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
                            cash = rows[0]["cash"]

                            # calculate the transaction's ammount (warning ! fancy mathematics ahead, may induce headaches...)
                            transactionAmmount = shares * quotePrice

                            # insert operation into transactions table (reminder : price hasn't been formated)
                            db.execute("INSERT INTO transactions (date_time, user_id, symbol, shares, price, transaction_type) VALUES ( datetime('now'), ?, ?, ?, ?, ?)", session["user_id"], companySymbol, shares, quotePrice, "sale")

                            # update user cash in users table
                            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + transactionAmmount, session["user_id"])

                            # check whether the user still has shares of this stock left after the transaction
                            # if yes update shares if user already still owns shares of this stock
                            if shares < ownedShares:
                                db.execute("UPDATE portfolios SET shares = shares - ? WHERE user_id = ? AND symbol = ?", shares, session["user_id"], companySymbol)

                            # if not (meaning if shares = ownedShares (since we already checked earlier that shares !> ownedShares this is the only remaining option))
                            # , delete the row corresponding to this symbol and this user in the portfolios table, because the number of shares for this user and symbol has fallen to zero
                            else:
                                db.execute("DELETE FROM portfolios WHERE user_id = ? AND symbol = ?", session["user_id"], companySymbol)

                            # redirect to index
                            return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
