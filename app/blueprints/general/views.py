from flask import Blueprint, render_template

general_blueprint = Blueprint('general', __name__, template_folder='templates')
@general_blueprint.route('/')
def to_main():
	return render_template('layout.html')
