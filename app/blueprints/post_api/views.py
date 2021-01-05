from flask import Blueprint, redirect, request, render_template, flash, url_for, current_app, jsonify, make_response, abort
from app.models import User, Post
from app import db
from app.forms import PostForm, UpdatePostForm
from flask_login import login_required, current_user
import datetime
from config import ROWS_PER_PAGE
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

postapi_blueprint = Blueprint('postsapi', __name__, template_folder='templates')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, 'SECRET_KEY')
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@postapi_blueprint.route('/api/posts',methods=['GET', 'POST'])
def posts():
    
    posts = Post.query.all()
    output = []

    for post in posts:
        post_data = {}
        post_data['id'] = post.id
        post_data['title'] = post.title
        post_data['body'] = post.body
        post_data['timestamp'] = post.timestamp
        post_data['updatetime'] = post.updatetime
        post_data['user_id'] = post.user_id
        output.append(post_data)

    return jsonify({'posts' : output})


@postapi_blueprint.route('/api/post/<id>',methods=['GET', 'POST'])
def post(id):
    
    post = Post.query.filter_by(id=id).first()
    if not post:
        return jsonify({'message' : 'No user found!'})

    post_data = {}
    post_data['id'] = post.id
    post_data['title'] = post.title
    post_data['body'] = post.body
    post_data['timestamp'] = post.timestamp
    post_data['updatetime'] = post.updatetime
    post_data['user_id'] = post.user_id
    

    return jsonify({'post' : post_data})


@postapi_blueprint.route('/api/login', methods=['GET', 'POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


    if user and user.check_password(auth.password):
        token = jwt.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, 'SECRET_KEY')

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})





@postapi_blueprint.route('/api/post/<id>', methods=['DELETE'])
@token_required
def delete_post(current_user, id):
    post = Post.query.get(id)
    if not post:
        return jsonify({'message' : 'No post found!'})
    db.session.delete(post)
    db.session.commit()
    flash("Product was deleted", category="info")

    return jsonify({'message' : 'The post has been deleted!'})


@postapi_blueprint.route('/api/post/<id>/update', methods=['GET', 'POST'])
@token_required
def update_post(current_user, id):
    post = Post.query.get(id)
    req = request.json
    if not req :
        abort(400)
    if not post:
        return jsonify({'message' : 'No post found!'})
    
    post.title = req.get('title')
    post.body = req.get('body')
    post.updatetime = datetime.datetime.utcnow()
    db.session.commit()

    return jsonify({'message' : 'The post has been updated!'})


@postapi_blueprint.route('/api/post/create', methods=['GET', 'POST'])
@token_required
def create_post(current_user):
    req = request.json
    if not req :
        abort(400)
    
    post = Post(title=req.get('title'), body=req.get('body'), author=current_user)
    
    post.updatetime = datetime.datetime.utcnow()
    db.session.add(post)
    db.session.commit()

    return jsonify({'message' : 'The post has been created!'})


    



