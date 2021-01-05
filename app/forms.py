from flask_login import current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, TextField
from wtforms.validators import InputRequired, Length, Email, EqualTo, DataRequired, ValidationError, Regexp
from app import bcrypt
from app.models import  User
from flask_admin.contrib.sqla import ModelView
from flask_admin.form import rules
from wtforms.widgets import TextArea

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired('A username is required')])
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[Length(min=4, max=25,
                                              message='This field length must be between 4 and 25 characters'),
                                              DataRequired('This field is required'),
                                              Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                              'Username must have only '
                                              'letters, numbers, dots or '
                                              'underscores')])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Length(min=6, message="Length of password should be greater than 6")])
    password_confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sing up')


    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[Length(min=4, max=25,
                                                          message="Username length should be between 4 and 25"),
                                                   DataRequired(message="This field can't be empty"),
                                                   Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                          'Username must have only '
                                                          'letters, numbers, dots or '
                                                          'underscores')])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    about_me = TextAreaField('About me', render_kw={'rows': 5}, validators=[Length(min=0, max=50)])
    old_password = PasswordField('Old password')
    new_password = PasswordField('New password')
    confirm_new_password = PasswordField('Confirm new password')
    submit = SubmitField('Update')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Email already registered')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username already registered')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    body = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Add  new post')


class UpdatePostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    body = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Update')
    submit2 = SubmitField('Delate Post')


class AdminUserCreateForm(FlaskForm):
    username = TextField('Username', [InputRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', [InputRequired()])
    password_confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    admin = BooleanField('Is Admin ?')
    submit = SubmitField('Create')


class AdminUserUpdateForm(FlaskForm):
    username = TextField('Username', [InputRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    admin = BooleanField('Is Admin ?')
    submit = SubmitField('Update')


class UserAdminView(ModelView):
    column_searchable_list = ('username',)
    column_sortable_list = ('username', 'admin')
    column_exclude_list = ('about_me', 'last_seen')
    form_excluded_columns = ('password_hash', 'last_seen')
    form_edit_rules = ('username', 'admin')


    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def scaffold_form(self):
        form_class = super(UserAdminView, self).scaffold_form()
        form_class.password = PasswordField('Password')
        form_class.new_password = PasswordField('New Password')
        form_class.confirm = PasswordField('Confirm New Password')
        return form_class

    def create_model(self, form):
        model = self.model(username=form.username.data, password_hash=bcrypt.generate_password_hash(form.password.data),admin=form.admin.data)
        form.populate_obj(model)
        self.session.add(model)
        self._on_model_change(form, model, True)
        self.session.commit()

    form_edit_rules = (
        'username', 'admin',
        rules.Header('Reset Password'),
        'new_password', 'confirm'
        )
    form_create_rules = (
        'username', 'admin', 'about_me', 'password'
        )      

    def update_model(self, form, model):
        form.populate_obj(model)
        if form.new_password.data:
            if form.new_password.data != form.confirm.data:
                flash('Passwords must match')
                return
            model.pwdhash = generate_password_hash(form.new_password.data)
        self.session.add(model)
        self._on_model_change(form, model, False)
        self.session.commit()
    

class CKEditorWidget(TextArea):
    def __call__(self, field, **kwargs):
        if kwargs.get('class'):
            kwargs['class'] += " ckeditor"
        else:
            kwargs.setdefault('class', 'ckeditor')
        return super(CKEditorWidget, self).__call__(field, **kwargs)


class CKEditorField(TextAreaField):
    widget = CKEditorWidget()



class PostAdminView(ModelView):
    form_overrides = dict(body=CKEditorField)
    can_view_details = True
    create_template = 'edit.html'
    edit_template = 'edit.html'

    column_exclude_list = ('timestamp', )
    column_searchable_list = ('id', 'title' )
    column_sortable_list = ('title', 'updatetime', 'title')
    column_filters = ('title', 'timestamp')
    