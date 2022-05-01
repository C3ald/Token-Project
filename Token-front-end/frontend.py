from flask import Flask, redirect, url_for, render_template, request, session, flash
from datetime import datetime, timedelta
import datetime
from pydantic.types import NoneBytes
import requests as r
import socket
# from passlib.hash import argon2
# from wallet import Wallet


app = Flask(__name__)
app.secret_key = "fdakjwklhfdvbeapwfjpawejufdva[pkdfoea=ffaslfjdanlweofuiajppsedfnjhapenvaevadafeafadrhreagfv"
app.permanent_session_lifetime = timedelta(days=2)
S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# wallets = Wallet()
URL = 'https://token-node0.herokuapp.com/'

		


@app.route('/')
def index():
	""" Shows index """
	return render_template('index.html')

@app.route('/blockchain-test')
def chain():
	""" the blockchain page """
	data = r.get(URL + 'get_the_chain')
	data = data.json()
	return render_template('blockchain.html', data=data)


@app.route('/about')
def about():
	""" Shows about page """
	return render_template('about.html')

@app.route('/login_wallet', methods=["POST","GET"])
def login():
	if request.method == "POST":
		publickey = str(request.form["publickey"])
		url = (f'{URL}check_balance')
		data = {'publickey': publickey}
		wallet = r.post(url, json=data)
		wallet = wallet.json()
		return render_template("view_wallet.html",wallet=wallet)
	
	return render_template("login.html")



@app.route('/wallet')
def wallet():
	""" Shows wallet and transactions pages """
	return render_template('wallet.html')


@app.route('/becomenode')
def becomenode():
	""" Shows wallet and transactions page """
	return render_template('becomenode.html')


@app.route('/makekeys')
def makekeys():
	""" allows you to make a wallet """
# 	data=r.get(f"{URL}create_keys")
# 	data=data.json()
# 	return render_template('make_keys.html',data=data)
	return render_template('make_keys.html')


@app.route('/mining')
def mining():
	""" Shows mining page """
	return render_template('mining.html')


# @app.route('/transact')
# def transact():
# 	""" Shows transactions page """
# 	if request.method == "POST":
# 		url = r.post(f'{URL}add_transaction')
# 		sender_public = request.form['senderpublickey']
# 		sender_private = request.form['senderprivatekey']
# 		# sender_phrase = request.form['senderpassphrase']
# 		receiver_public = request.form['receiverpublickey']
# 		amount = float(request.form['amount'])
# 		data =     {'sender_publickey': sender_public,
#     		    'sender_privatekey': sender_private,
#     		    'receiver': receiver_public,
#     		    'amount': amount}
# 		transaction = r.post(url=url, json=data)
# 		return render_template('transactions.html')
# 	return render_template('transactions.html')


@app.route('/home')
def home():
	""" Shows index """
	return render_template('index.html')


@app.route('/index')
def index1():
	""" Shows index """
	return render_template('index.html')


@app.route('/blockchain')
def blockchain():
	""" the blockchain page """
	data = r.get(f'{URL}get_the_chain')
	data = data.json()
	return render_template('blockchain.html', data=data)


@app.route('/404')
def snack():
	""" 404 page """
	return render_template('404.html')

#TODO Make functioning login and register page using sql alchemy, flask, and html
#TODO Mkae all templates injectable
# @app.route('/register', methods=['POST','GET'])
# def register():
# 	""" the page where you make an account """
# 	return render_template('register.html')

# @app.route('/register', methods =['POST', 'GET'])
# def login_user():
# 	""" to add a user """
# 	if "user" and "passw" in session:
# 		flash("already logged in")
# 		return redirect(url_for('login_wallet'))
# 	if request.method == "POST":
# 		user = request.form['username']
# 		passw = request.form['password']
# 	else:	
# 		return redirect(url_for("login", user='user', passw='passw'))
		
		


# @app.route("/logout")
# def logout():
# 	""" the page to logout """
# 	if "user" in session:
# 		flash("logout was successful")
# 	session.pop("user", None)
# 	session.pop("username", None)
# 	return redirect(url_for("login"))


@app.route('/become_node')
def become_node():
	""" page to become a node """
	return render_template("become_node.html")


# @app.route("/playground")
# def playground():
# 	""" the testing page """
# 	data = r.get('http://localhost:8000/get_the_chain')
# 	data = data.json()
# 	return render_template("playground_index.html", data=data)
@app.route("/playground")
def playground():
	""" Testing page """
	# users = Users.query.all()
	return render_template("playground.html")

# @app.route("/add/user/<user>/<password>")
# def add_user(user, password):
# 	""" add a user """
# 	hash = argon2.hash(password)
# 	user = Users(username=user, password=hash)
# 	db.session.add(user)
# 	db.session.commit()
# 	return redirect(url_for('playground'))


# @app.route("/authenticate/user/<user>/<passoword>")
# def authenticate(user, password):
# 	""" verifies the user """
# 	hash = Users.query.filter_by(username=user).first()
# 	result = argon2.verify(password, hash.password)
# 	return str(result)


# @app.route('/blog')
# def blog():
# 	""" the blog route """
# 	blogs = [{
# 		"title":"This is the first post",
# 		"date":datetime.datetime.utcnow(),
# 		"author": "author",
# 		"body":"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
# 	}]
# 	return render_template('blog.html', blogs=blogs)


if __name__ == "__main__":
	app.run(host='127.0.0.1', port=8000, debug=False)
