import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, flash
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Clear Cache
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    try:
        stocks = db.execute('SELECT symbol, SUM(shares) AS total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0', session['user_id'])

        total = 0
        for stock in stocks:
            # Add total stock price to the data based on the current price from YAHOO finance
            stock['current_price'] = lookup(stock['symbol'])['price']
            total += stock['current_price'] * stock['total_shares']

        current_cash = db.execute('SELECT cash FROM users WHERE id = ?', session['user_id'])[0].get('cash')
        current_cash = float(current_cash)

        return render_template('index.html', cash=current_cash, stocks=stocks, total=total)
   
    except:
        session.clear()
        return redirect("/")
    
@app.route("/wallet", methods=["GET", "POST"])
@login_required
def wallet():
    """Increase credit balance"""

    if request.method == "GET":
        return(render_template('wallet.html'))
    
    else:
        
        amount = request.form.get('amount')
        try:
            amount = float(amount)
            if not amount or float(amount) <= 0:
                return apology('please enter a positive amount')
        except:
            return apology('bad input')
        
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", amount, session['user_id'])

        flash(f'Balance successfully increased by ${amount}')
        return redirect("/")
        
@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template('buy.html')
    
    else:

        # Check user inputs
        symbol = request.form.get('symbol')
        shares = request.form.get('shares')

        if not symbol or not shares:
            return apology("fill the blanks")
        
        stock = lookup(symbol)
        current_cash = db.execute('SELECT cash FROM users WHERE id = ?', session['user_id'])[0].get('cash')
        current_cash = float(current_cash) 
        
        try:
            shares = int(shares)
        except:
            return apology('bad input')
        
        if shares <= 0 :
            return apology('number of shares should be positive')
        
        elif stock is None:
            return apology('invalid symbol')
        
        elif current_cash < (purchase := shares * stock['price']):
            # Check if user has enough cash
            return apology("cant't afford")

        db.execute('UPDATE users SET cash = ? WHERE id = ?',
                   current_cash - purchase, session['user_id'])
        
        db.execute('INSERT INTO transactions(user_id, symbol, shares, price) VALUES(?, ?, ?, ?)',
                   session['user_id'], stock['symbol'], shares, stock['price'])
        
        flash('Bought!')
        return redirect('/')

        
@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute('SELECT symbol, shares, price, timestamp FROM transactions WHERE user_id = ?', session['user_id'])
    print('salaaaaaam', transactions)
    print(session['user_id'])
    return render_template('history.html', transactions=transactions)

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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("Welcome!")
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

    if request.method == 'POST':
        quote = request.form.get('symbol')
        # Make sure that quote is not empty
        if not quote:
            return apology('missing symbol')
        
        quote = lookup(quote)
        # Make sure that symbol is valid
        if not quote:
            return apology('invalid symbol')
        else:
            return render_template('quoted.html', quote=quote)

    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
    
        # Get the user inputs
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        # Ensure username and password were submitted
        if not username or not password:
            return apology('username/passowrd cannot be empty!', 400)

        # Ensure that password and confirmation are the same
        elif password != confirmation:
            return apology('passwords do not match', 400)   
        
        try:
            db.execute('INSERT INTO users (username, hash) VALUES (?, ?)',
                        username, generate_password_hash(password))
        except ValueError:
            return apology('username already exists!', 400)

        # Redirect user to the login page
        flash('Successfuly Registered!')
        return redirect("/login")

    else:
        return render_template("register.html")




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == 'GET':
        # Showing current stocks
        stocks = db.execute('SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0', session['user_id'])
        return render_template('sell.html', stocks=stocks)
    else:

        stocks = db.execute('SELECT symbol, SUM(shares) AS total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0', session['user_id'])
        symbol = request.form.get('symbol')
        shares = request.form.get('shares')

        symbols_dict = {stock.get('symbol'): stock.get('total_shares') for stock in stocks}

        # Check user input
        if not symbol or not shares:
            return apology('fill the blanks')
        
        elif symbol not in list(symbols_dict.keys()):
            return apology('symbol is not available')
        
        try:
            shares = int(shares)
        except:
            return apology('bad input')
        
        if shares <= 0 :
            return apology("you can't sell a non-positive amount")
        
        elif shares > symbols_dict.get(symbol):
            return apology("not enough shares")
        
        
        stock = lookup(symbol)
        db.execute('INSERT INTO transactions(user_id, symbol, shares, price) VALUES(?, ?, ?, ?)', session['user_id'], stock['symbol'], -shares, stock['price'])
        db.execute('UPDATE users SET cash = cash + ? WHERE id = ?', stock['price'] * shares, session['user_id'])

        flash('Sold!')
        return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)