from flask import Blueprint, render_template, request, flash, redirect, url_for, abort
from app.models import User, Post
from flask_login import login_required, current_user
from functools import wraps
from app.forms import AdminUserUpdateForm, AdminUserCreateForm
from app import db

administrator_blueprint = Blueprint('administrator', __name__, template_folder='templates')

def admin_login_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_admin():
            return abort(403)
        return func(*args, **kwargs)
    return decorated_view

@administrator_blueprint.route('/administrator')
@login_required
@admin_login_required
def home_admin():
    return render_template('administrator/admin-home.html')


@administrator_blueprint.route('/administrator/users-list')
@login_required
@admin_login_required
def users_list_admin():
    users = User.query.all()
    return render_template('administrator/users-list-admin.html', users=users)


@administrator_blueprint.route('/administrator/create-user', methods=['GET', 'POST'])
@login_required
@admin_login_required
def user_create_admin():
    form = AdminUserCreateForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        admin = form.admin.data
        user = User(username=username, email=email, password_hash=hashed, admin=admin)
        db.session.add(user)
        db.session.commit()
        flash("User added")
        return redirect(url_for('administrator.home_admin'))

    return render_template('administrator/user-create-admin.html', form=form)


@administrator_blueprint.route('/administrator/update-user/<id>', methods=['GET', 'POST'])
@login_required
@admin_login_required
def user_update_admin(id):
    form = AdminUserUpdateForm()
    user = User.query.filter_by(id=id).first()
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.admin = form.admin.data
        db.session.commit()
        flash("User was updated", category="info")
        return redirect(url_for('administrator.home_admin'))

    return render_template('administrator/user-update-admin.html', form=form, user=user)


@administrator_blueprint.route('/administrator/delete-user/<id>')
@login_required
@admin_login_required
def user_delete_admin(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    flash("User was deleted", category="info")
    return render_template('administrator/admin-home.html')
