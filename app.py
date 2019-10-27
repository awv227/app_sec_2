#Application Security
#Andrew Vittetoe
#05OCT2019
#Assignment #2


# importing modules
import os
from flask import Flask, render_template, request, flash, url_for, session, redirect
from flask_session import Session
from flask_wtf import FlaskForm
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from spellchecker import SpellChecker
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError

# initializing a variable of Flask
app = Flask(__name__)


# Set secure cookies
app.session_cookie_secure = True
app.remember_cookie_secure = True
# Set HTTP Only
app.session_cookie_httponly = True
app.remember_cookie_httponly = True
# Lifetime set to 1 minute
app.permanent_session_lifetime = 60
app.session_permanent = False
# Set secret key
app.secret_key = os.environ.get('SECRET_KEY') or '6\xe9\xda\xead\x81\xf7\x8d\xbbH\x87\xe8m\xdd3%'


# Instead of DB, use Dict
test = {
  "uname" : "",
  "pword" : "",
  "ID_2fa" : ""
}
userList = {
  "test" : test,
}

unameSuccess = "false"
pwordSuccess = "false"
ID_2faSuccess = "false"
success = ""
result = ""

# Routes -----------------------------------------------------------------------------------------------------------------------------------------

# Home page / register
@app.route('/', methods=['POST','GET'])
@app.route("/home", methods=['POST','GET'])
@app.route("/register", methods=['POST','GET'])
def register():
    form = RegisterForm()
    success = ""

    # If submitted and validated, save info but do not login
    if form.validate_on_submit():

        uname = form.uname.data
        ID_2fa = generate_password_hash(form.ID_2fa.data)
        pword = generate_password_hash(form.pword.data)

        # Add to userList
        i = len(userList)+1
        userList[i] = {}
        userList[i]["uname"] = uname
        userList[i]["pword"] = pword
        userList[i]["ID_2fa"] = ID_2fa

        # Return success
        success = "succcess"

    # Doesn't pass validation
    else:
        success = "failure"

    return render_template("register.html", title="Register", form=form, register=True, success=success)


# Login page
@app.route("/login", methods=['GET','POST'])
def login():
    form = LoginForm()
    result = ""
    unameSuccess = "false"
    pwordSuccess = "false"
    ID_2faSuccess = "false"

    if form.validate_on_submit():
        uname = form.uname.data
        ID_2fa = form.ID_2fa.data
        pword = form.pword.data

        for user, user_info in userList.items():
            for user_key in user_info:
                if user_key == "uname":
                    if user_info[user_key] == uname:
                        unameSuccess = "true"
                        break

        for user, user_info in userList.items():
            for user_key in user_info:
                if user_key == "pword":
                    if check_password_hash(user_info[user_key], form.pword.data):
                        pwordSuccess = "true"
                        break
        for user, user_info in userList.items():
            for user_key in user_info:
                if user_key == "ID_2fa":
                    if check_password_hash(user_info[user_key], form.ID_2fa.data):
                        ID_2faSuccess = "true"
                        break

        if unameSuccess == "true" and pwordSuccess == "true" and ID_2faSuccess == "true":
            result = "success"
            session['id'] = uuid.uuid1()
        elif unameSuccess == "false":
            result = "incorrect"
        elif pwordSuccess == "false":
            result = "incorrect"
        elif ID_2faSuccess == "false":
            result = "Two-factor failure"
    
    # Doesn't pass validation
    else:
        result = "failure"
    
    return render_template("login.html", title="Login", form=form, login=True, result=result)

# Spell_Check page
@app.route("/spell_check", methods=['GET','POST'])
def spell_check():

    # If not logged in, send to login page and stop
    if not session.get('id'):
        return redirect(url_for('login'))

    form = SpellCheckForm()
    textout = []
    misspelled = []
    
    # See if text is validated
    if form.validate_on_submit():
        spell = SpellChecker()
        inputtext = form.inputtext.data

        # Parse text
        words = inputtext.split()

        # Find out if words are misspelled
        for word in words:
            if word in spell:
                textout.append(word)
            else:
                misspelled.append(word)

    return render_template("spell_check.html", title="Spell Check", form=form, spell_check=True, textout=textout, misspelled=misspelled)


# FORMS ---------------------------------------------------------------------------------------------------------------------------
class LoginForm(FlaskForm):
    uname = StringField("Enter Username", validators=[DataRequired(), Length(min=2,max=55)])
    pword = PasswordField("Enter Password", validators=[DataRequired(), Length(min=4,max=15)])
    ID_2fa = StringField("Enter 2FA", validators=[DataRequired(), Length(min=2,max=55)])
    submit = SubmitField("Login")


class RegisterForm(FlaskForm):
    uname = StringField("Create Username", validators=[DataRequired(),Length(min=2,max=55)])
    pword = PasswordField("Enter Password", validators=[DataRequired(),Length(min=4,max=15)])
    ID_2fa = StringField("Set 2FA", validators=[DataRequired(),Length(min=2,max=55)])
    password_confirm = PasswordField("Confirm Password", validators=[DataRequired(),Length(min=4,max=15), EqualTo('pword')])
    submit = SubmitField("Register Now")

    #Check that uname doesn't already exist
    def validate_uname(self, uname):
        for user, user_info in userList.items():
            for user_key in user_info:
                if user_key == "uname":
                    if user_info[user_key] == uname:
                        self.errors.append("Username is already in use. Pick another one.")
                        #raise ValidationError("Username is already in use. Pick another one.")


class SpellCheckForm(FlaskForm):
    inputtext = StringField("Enter Text to Spell Check", validators=[DataRequired(), Length(min=2,max=5000)])
    check_spelling = SubmitField("Check Spelling")

# Run with Debug? -----------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    app.debug = True
    app.run()  