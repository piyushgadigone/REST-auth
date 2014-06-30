from flask.ext.wtf import Form
from wtforms.fields import TextField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import Required
 
class RegisterForm(Form):
  username = TextField("Username", [Required("Please enter your username.")])
  password = PasswordField('Password', [Required("Please enter your password.")])	
  confirm_password = PasswordField('Confirm Password', [Required("Please confirm your password.")])
  submit = SubmitField("Register")