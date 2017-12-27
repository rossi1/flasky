from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import ValidationError, Email, DataRequired, Length, EqualTo
from .model import User


class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired('This field is required'), Email('invalid email')])
    username = StringField('Username', validators=[DataRequired('This field is required'), Length(min=6, max=8)])
    password = PasswordField('Password', validators=[DataRequired('This field is required')])
    reconfirm_password = PasswordField('Confirm passowrd', validators=[DataRequired(), EqualTo('password')])
    area_code = StringField('Area code', validators=[DataRequired('This field is required')])
    phone_number = StringField('Phone number', validators=[DataRequired('This field is required')])
    submit = SubmitField('Register')


    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already exist')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already exit')


class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired('This field is required'), Email('invalid email')])
    password = PasswordField('password', validators=[DataRequired('This field is required')])
    submit = SubmitField('Sign-in')


class AuthForm(FlaskForm):
    auth_code = StringField('auth_code', validators=[DataRequired('This field is required')])
    submit = SubmitField('Sign-in')

