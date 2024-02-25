from flask import Flask,render_template,redirect,url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,IntegerField
from wtforms.validators import Length,EqualTo,Email,DataRequired,ValidationError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager,login_user,UserMixin,logout_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///market.db'
app.config['SECRET_KEY']="6a38e57515e36670ffaa1d5a"

db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
login_manager=LoginManager(app)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):

    def validate_username(self,username_to_check):
        user=User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exists!Please try a different username')

    def validate_email_address(self,email_address_to_check):
        user = User.query.filter_by(email_address=email_address_to_check.data).first()
        if user:
            raise ValidationError('Email already exists!Please try a different email id')
    username=StringField(label='Username',validators=[Length(min=2,max=30),DataRequired()])
    email_address=StringField(label='Email',validators=[Email(),DataRequired()])
    password1=PasswordField(label='Password',validators=[Length(min=6),DataRequired()])
    password2=PasswordField(label='Enter Password Again',validators=[EqualTo('password1'),DataRequired()])
    submit=SubmitField(label='Submit')

class LoginForm(FlaskForm):
    username = StringField(label='Username')
    password = PasswordField(label='Enter Password')
    submit = SubmitField(label='Submit')

class CounsellingForm(FlaskForm):
    name= StringField(label='Student Name')
    email_address=StringField(label='Email',validators=[Email(),DataRequired()])
    problem=StringField(label='Problem Faced')
    submit = SubmitField(label='Submit')

class User(db.Model,UserMixin):
    id=db.Column(db.Integer(),primary_key=True)
    username=db.Column(db.String(length=30),nullable=False,unique=True )
    email_address=db.Column(db.String(length=50),nullable=False,unique=True )
    password_hash=db.Column(db.String(length=60),nullable=False)


    @property
    def password(self):
        return self.password

    @password.setter
    def password(self,plain_text_password):
        self.password_hash=bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password(self,attempted_password):
        return bcrypt.check_password_hash(self.password_hash,attempted_password)

class Counselling(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String,nullable=False)
    email=db.Column(db.String,nullable=False)
    problem = db.Column(db.String, nullable=False)




@app.route("/login",methods=['GET','POST'])
def login_page():
    form=LoginForm()
    if form.validate_on_submit():
        attempted_user=User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password(attempted_password=form.password.data):
            login_user(attempted_user)
            flash(f'Success!You are logged in as:{attempted_user.username}',category='success')
            return redirect(url_for('market_page'))
        else:
            flash('Login not successful!Please try again',category='danger')
    return render_template("login.html",form=form)

@app.route("/")
def home_page():
    return render_template("home.html")

@app.route("/register",methods=['GET','POST'])
def register_page():
    form=RegisterForm()
    if form.validate_on_submit():
        user_to_create=User(username=form.username.data,
                            email_address=form.email_address.data,
                            password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        return redirect(url_for("login_page"))

    if form.errors !={}:
        for err_msg in form.errors.values():
            flash(f"There was an error while creating the user:{err_msg}",category='danger')
    return render_template("register.html",form=form)


@app.route("/logout")
def logout_page():
    logout_user()
    flash("You have been logged out",category='info')
    return redirect(url_for('register_page'))




@app.route("/counselling",methods=['GET','POST'])
def counselling_page():
    form=CounsellingForm()
    if form.validate_on_submit():
        counselling_entry=Counselling(name=form.name.data,
                                      email=form.email_address.data,
                                      problem=form.problem.data)
        db.session.add(counselling_entry)
        db.session.commit()
        return redirect(url_for("counselling_page"))
    if form.errors !={}:
        for err_msg in form.errors.values():
            flash(f"There was an error during the counselling process:{err_msg}",category='danger')
    return render_template("Counselling.html",form=form)


@app.route("/about")
def about_us():
    return render_template("about.html")

@app.route("/nda")
def nda_page():
    return render_template("nda.html")

@app.route("/nda_maths")
def nda_maths_page():
    return render_template("nda_maths.html")

@app.route("/nda_general_ability_test")
def nda_general_ability_test_page():
    return render_template("nda_general_ability_test.html")

@app.route("/nda_physical_fitness_training")
def nda_physical_fitness_training_page():
    return render_template("nda_physical_fitness_training.html")


@app.route("/iitjee")
def jee_page():
    return render_template("iitjee.html")


@app.route("/iitjee_physics")
def jee_physics_page():
    return render_template("iitjee_physics.html")

@app.route("/iitjee_maths")
def jee_maths_page():
    return render_template("iitjee_maths.html")

@app.route("/iitjee_chemistry")
def jee_chemistry_page():
    return render_template("iitjee_chemistry.html")


@app.route("/neet")
def neet_page():
    return render_template("neet.html")

@app.route("/neet_biology")
def neet_biology_page():
    return render_template("neet_biology.html")

@app.route("/neet_chemistry")
def neet_chemistry_page():
    return render_template("neet_chemistry.html")

@app.route("/neet_physics")
def neet_physics_page():
    return render_template("neet_physics.html")





