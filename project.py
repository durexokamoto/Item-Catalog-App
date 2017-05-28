from flask import Flask, render_template, request, redirect, jsonify, url_for, flash


from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Catagory, Item, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catagory Menu Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalogwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# Google login
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# JSON APIs to view Catagory Information
@app.route('/catagory/<int:catagory_id>/items/JSON')
def catagoryItemsJSON(catagory_id):
    catagory = session.query(Catagory).filter_by(id=catagory_id).one()
    items = session.query(Item).filter_by(
        catagory_id=catagory_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/catagory/<int:catagory_id>/items/<int:item_id>/JSON')
def itemJSON(catagory_id, item_id):
    oneItem = session.query(Item).filter_by(id=item_id).one()
    return jsonify(oneItem=oneItem.serialize)


@app.route('/catagory/JSON')
def catagoriesJSON():
    catagories = session.query(Catagory).all()
    return jsonify(catagories=[r.serialize for r in catagories])


# Show all catagories
@app.route('/')
@app.route('/catagory/')
def showCatagories():
    catagories = session.query(Catagory).order_by(asc(Catagory.name))
    if 'username' not in login_session:
        return render_template('publicCatagories.html', catagories=catagories)
    else:
        return render_template('catagories.html', catagories=catagories)


# Create a new catagory
@app.route('/catagory/new/', methods=['GET', 'POST'])
def newCatagory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCatagory = Catagory(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newCatagory)
        flash('New Catagory %s Successfully Created' % newCatagory.name)
        session.commit()
        return redirect(url_for('showCatagories'))
    else:
        return render_template('newCatagory.html')


# Edit a catagory
@app.route('/catagory/<int:catagory_id>/edit/', methods=['GET', 'POST'])
def editCatagory(catagory_id):
    if 'username' not in login_session:
        return redirect('/login')
    catagoryToEdit = session.query(
        Catagory).filter_by(id=catagory_id).one()
    if catagoryToEdit.user_id != login_session['user_id']:
        flash('You are not authorized to edit this catagory. Please create your own catagory in order to edit.')
        return redirect(url_for('showCatagories'))
    if request.method == 'POST':
        if request.form['name']:
            catagoryToEdit.name = request.form['name']
            flash('Catagory Successfully Edited %s' % catagoryToEdit.name)
            return redirect(url_for('showCatagories'))
    else:
        return render_template('editCatagory.html',
                               catagory=catagoryToEdit)


# Delete a catagory
@app.route('/catagory/<int:catagory_id>/delete/', methods=['GET', 'POST'])
def deleteCatagory(catagory_id):
    if 'username' not in login_session:
        return redirect('/login')
    catagoryToDelete = session.query(Catagory).filter_by(id=catagory_id).one()
    if catagoryToDelete.user_id != login_session['user_id']:
        flash('You are not authorized to delete this catagory. Please create your own catagory in order to delete.')
        return redirect(url_for('showCatagories',
                                catagory_id=catagory_id))
    if request.method == 'POST':
        session.delete(catagoryToDelete)
        flash('%s Successfully Deleted' % catagoryToDelete.name)
        session.commit()
        return redirect(url_for('showCatagories',
                                catagory_id=catagory_id))
    else:
        return render_template('deleteCatagory.html',
                               catagory=catagoryToDelete)


# Show a list of items
@app.route('/catagory/<int:catagory_id>/')
@app.route('/catagory/<int:catagory_id>/items/')
def showItems(catagory_id):
    catagory = session.query(Catagory).filter_by(id=catagory_id).one()
    creator = getUserInfo(catagory.user_id)
    items = session.query(Item).filter_by(
        catagory_id=catagory_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicItems.html',
                               items=items,
                               catagory=catagory,
                               creator=creator)
    else:
        return render_template('items.html',
                               items=items,
                               catagory=catagory,
                               creator=creator)


# Create a new item
@app.route('/catagory/<int:catagory_id>/items/new/',
           methods=['GET', 'POST'])
def newItem(catagory_id):
    if 'username' not in login_session:
        return redirect('/login')
    catagory = session.query(Catagory).filter_by(id=catagory_id).one()
    if request.method == 'POST':
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       price=request.form['price'],
                       catagory_id=catagory_id,
                       user_id=catagory.user_id)
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showItems', catagory_id=catagory_id))
    else:
        return render_template('newItem.html', catagory_id=catagory_id)


# Edit an item
@app.route('/catagory/<int:catagory_id>/items/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editItem(catagory_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToEdit = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        if request.form['name']:
            itemToEdit.name = request.form['name']
        if request.form['description']:
            itemToEdit.description = request.form['description']
        if request.form['price']:
            itemToEdit.price = request.form['price']
        session.add(itemToEdit)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showItems', catagory_id=catagory_id))
    else:
        return render_template('editItem.html',
                               catagory_id=catagory_id,
                               item_id=item_id,
                               item=itemToEdit)


# Delete an item
@app.route('/catagory/<int:catagory_id>/items/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(catagory_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showItems', catagory_id=catagory_id))
    else:
        return render_template('deleteItem.html', item=itemToDelete)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
