from flask.ext.wtf import Form
from wtforms.fields import TextField, SubmitField
from wtforms.validators import Required
 
class TwoStepForm(Form):
  username = TextField("Username", [Required("Please enter your username.")])
  two_step_token = TextField("", [Required("Please enter your OTP.")])
  submit = SubmitField("Login")
