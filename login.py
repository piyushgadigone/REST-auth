from flask.ext.wtf import Form
from wtforms.fields import TextField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import Required
 
class LoginForm(Form):
  username = TextField("Username", [Required()])
  password = PasswordField('Password', [Required()])	
  submit = SubmitField("Login")
