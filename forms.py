
from wtforms import StringField, IntegerField

from wtforms.validators import DataRequired, NumberRange
from flask_wtf import FlaskForm, RecaptchaField


class get_token(FlaskForm):
    name = IntegerField('name', validators=[DataRequired(),NumberRange(min=10000, max=10000000000, message='Something')])
    recaptcha = RecaptchaField()
