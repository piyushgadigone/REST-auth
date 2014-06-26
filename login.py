from flask.ext.wtf import Form
from wtforms.fields import TextField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import Required
 
class LoginForm(Form):
  username = TextField("Username", [Required("Please enter your username.")])
  password = PasswordField('Password', [Required("Please enter your password.")])	
  submit = SubmitField("Login")
