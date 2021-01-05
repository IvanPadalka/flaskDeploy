from flask import Blueprint, render_template, flash, request, url_for, redirect
from flask_login import current_user, login_user, logout_user
from app.models import User
from app.forms import LoginForm, RegistrationForm
from app import db
from werkzeug.urls import url_parse
from datetime import datetime
from flask_bcrypt import generate_password_hash


auth_blueprint = Blueprint('auth', __name__, template_folder='templates')


@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('general.to_main'))

    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            flash(f'Welcome back {user.username}', 'info')
            login_user(user)
            
            return redirect(url_for('account.account'))
        else:
            flash(f'Incorrect email or password', 'warning')
        
    return render_template('auth/login.html', form=login_form)

@auth_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('general.to_main'))
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed = generate_password_hash(password).decode('utf-8')

        user = User(username=username, email=email, password_hash=hashed)
        db.session.add(user)
        db.session.commit()
        flash("Sing up successfully")
        return redirect(url_for('general.to_main'))
    return render_template('auth/register.html', form=form)


@auth_blueprint.route('/logout')
def logout():
    logout_user()
    flash('Logged out')
    return redirect(url_for('general.to_main'))

@auth_blueprint.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
