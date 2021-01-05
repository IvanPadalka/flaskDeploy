from flask import Blueprint, redirect, request, render_template, flash, url_for, current_app
from app.models import User, Post
from app import db
from app.forms import PostForm, UpdatePostForm
from flask_login import login_required, current_user
from datetime import datetime
from config import ROWS_PER_PAGE


post_blueprint = Blueprint('posts', __name__, template_folder='templates')


@post_blueprint.route('/posts',methods=['GET', 'POST'])
def posts():
    q = request.args.get('q')
    if q:
        posts = Post.query.filter(Post.title.contains(q) | Post.body.contains(q))
    else:
        posts = Post.query.order_by(Post.timestamp.desc())

    page = request.args.get('page', 1, type=int)
    posts = posts.paginate(page=page, per_page=ROWS_PER_PAGE)
    
    return render_template('post/posts.html', posts=posts, q=q)

@post_blueprint.route('/post/new', methods=['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, body=form.body.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash("Post was created", category="info")
        return redirect(url_for('posts.posts'))

    return render_template('post/create_post.html', form=form)

@post_blueprint.route('/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def post(post_id):
    post = Post.query.filter_by(id=post_id).first()
    form = UpdatePostForm()

    if current_user.username != post.author.username:
        flash("Its not your post", category="eror")
        return redirect(url_for('posts.posts'))

    elif form.validate_on_submit():
        post.title = form.title.data
        post.body = form.body.data
        post.updatetime = datetime.utcnow()
        db.session.commit()
        flash("Post was updated", category="info")
        return redirect(url_for('posts.post', post_id=post.id))

    elif "delete" in request.form:
        db.session.delete(post)
        db.session.commit()
        flash("Post deleted", category="eror")
        return redirect(url_for('posts.posts'))

    return render_template('post/post.html', post=post, form=form)


@post_blueprint.route('/post/delete/<int:post_id>', methods=['GET', 'POST'])
@login_required
def delete_post(post_id):
    pass
