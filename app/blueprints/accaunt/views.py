from flask import Blueprint, request, url_for, render_template
from flask_login import current_user, login_required 
from app.forms import UpdateAccountForm
import os


accaunt_blueprint = Blueprint('account', __name__, template_folder='templates')

@accaunt_blueprint.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.about_me = form.about_me.data
        if form.old_password.data:
            current_user.password_hash = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
        db.session.commit()
        flash('Your account has been updated!', 'success')
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.about_me.data = current_user.about_me
    image_file = url_for('static', filename='images/thumbnails/' + current_user.image_file)
    return render_template('accaunt/account.html', title='Account', image_file=image_file, form=form, user=current_user)


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    f_name, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = f_name + random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/images/thumbnails/', picture_fn)
    # form_picture.save(picture_path)

    output_size = (128, 128)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn
