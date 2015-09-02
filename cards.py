from flask import *
from flask_wtf import Form
from wtforms import IntegerField, StringField, PasswordField, SelectField, RadioField
from wtforms.validators import DataRequired, Length, NumberRange, EqualTo
from flask.ext.sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt
from Crypto.Cipher import AES
from Crypto import Random
import string, random, StringIO, base64, os, glob, csv, subprocess

#config
DEBUG = True
SECRET_KEY = 'ywp5yz0sf0'
SQLALCHEMY_DATABASE_URI='sqlite:///./cards.db'

app = Flask(__name__)
app.config.from_object(__name__)

db = SQLAlchemy(app)

#encryption
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]
class aescrypt(object):
    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(str(raw))
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) ) 

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))

class Auth(object):
	def __init__(self, username=None):
		if username:
			self.username=username.replace(" ","")
		else:
			self.username=False

	def hash(self, password):
		if self.username == True:
			return sha256_crypt.encrypt(password, salt=self.username)
		else:
			return sha256_crypt.encrypt(str(password))

	def verify(self, hash, password):
		return sha256_crypt.verify(password, hash)
#Databases
class Users(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.Text)
	password = db.Column(db.Text) #Must auth this password
	reset = db.Column(db.Integer)

	def __init__(self, **kwargs):
		for name, value in kwargs.items():
			self.__setattr__(name, value)

class Cards(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.Text)
	cvc = db.Column(db.Text)
	cardNumber = db.Column(db.Text)
	expireDate = db.Column(db.Text)
	clientReference = db.Column(db.Text)
	amount = db.Column(db.Text)
	user = db.Column(db.Text)

	def __init__(self, **kwargs):
		for name, value in kwargs.items():
			self.__setattr__(name, value)

class Password(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	password=db.Column(db.Text)

class Expiration(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	start = db.Column(db.Integer)
	end = db.Column(db.Integer)
#Forms
class LoginForm(Form):
	username=StringField('username', validators=[DataRequired()])
	password=PasswordField('password', validators=[DataRequired()])

class CardForm(Form):
	#card number
	pana=IntegerField('pana', validators=[DataRequired(message="Please enter a four digit number"), NumberRange(min=0, max=9999, message="Value must be between 0 and 9999")])
	panb=IntegerField('panb', validators=[DataRequired(message="Please enter a four digit number"), NumberRange(min=0, max=9999, message="Value must be between 0 and 9999")])
	panc=IntegerField('panc', validators=[DataRequired(message="Please enter a four digit number"), NumberRange(min=0, max=9999, message="Value must be between 0 and 9999")])
	pand=IntegerField('pand', validators=[DataRequired(message="Please enter a four digit number"), NumberRange(min=0, max=9999, message="Value must be between 0 and 9999")])
	#expiry

	#name
	name=StringField("Cardholder\'s Name", validators=[DataRequired()])
	#CV2
	CV2=IntegerField('CV2', validators=[DataRequired(), NumberRange(min=0, max=999, message="Value must be between 0 and 999")])
	#Reference
	reference=StringField('Customer Reference', validators=[DataRequired()])
	#amount
	amount=IntegerField("Amount Charged (GBP)", validators=[DataRequired()])

class PassForm(Form):
	password = PasswordField('password', validators=[DataRequired()])
	confirm = PasswordField('confirm', validators=[DataRequired(), EqualTo('password')])
class ChangeForm(Form):
	current = PasswordField('Current Password', validators=[DataRequired()])
	new = PasswordField('New Password', validators=[DataRequired()])
	confirm = PasswordField('Confirm password', validators=[DataRequired(), EqualTo('new')])
class NewUser(Form):
	username = StringField('username', validators=[DataRequired()])
	password = PasswordField('password', validators=[DataRequired()])
	confirm = PasswordField('confirm', validators=[DataRequired(), EqualTo('password')])
class ExpirationForm(Form):
	start = SelectField('Beginning of range', choices=[('1', '1'), ('2', '2'), ('3', '3'), ('4', '4'), ('5', '5'), ('6', '6'), ('7', '7'), ('8', '8'), ('9', '9'), ('10', '10'), ('11', '11'), ('12', '12'), ('13', '13'), ('14', '14'), ('15', '15'), ('16', '16'), ('17', '17'), ('18', '18'), ('19', '19'), ('20', '20'), ('21', '21'), ('22', '22'), ('23', '23'), ('24', '24'), ('25', '25'), ('26', '26'), ('27', '27'), ('28', '28'), ('29', '29'), ('30', '30'), ('31', '31'), ('32', '32'), ('33', '33'), ('34', '34'), ('35', '35'), ('36', '36'), ('37', '37'), ('38', '38'), ('39', '39'), ('40', '40'), ('41', '41'), ('42', '42'), ('43', '43'), ('44', '44'), ('45', '45'), ('46', '46'), ('47', '47'), ('48', '48'), ('49', '49'), ('50', '50'), ('51', '51'), ('52', '52'), ('53', '53'), ('54', '54'), ('55', '55'), ('56', '56'), ('57', '57'), ('58', '58'), ('59', '59'), ('60', '60'), ('61', '61'), ('62', '62'), ('63', '63'), ('64', '64'), ('65', '65'), ('66', '66'), ('67', '67'), ('68', '68'), ('69', '69'), ('70', '70'), ('71', '71'), ('72', '72'), ('73', '73'), ('74', '74'), ('75', '75'), ('76', '76'), ('77', '77'), ('78', '78'), ('79', '79'), ('80', '80'), ('81', '81'), ('82', '82'), ('83', '83'), ('84', '84'), ('85', '85'), ('86', '86'), ('87', '87'), ('88', '88'), ('89', '89'), ('90', '90'), ('91', '91'), ('92', '92'), ('93', '93'), ('94', '94'), ('95', '95'), ('96', '96'), ('97', '97'), ('98', '98'), ('99', '99')])
	end = SelectField('End of range', choices=[('1', '1'), ('2', '2'), ('3', '3'), ('4', '4'), ('5', '5'), ('6', '6'), ('7', '7'), ('8', '8'), ('9', '9'), ('10', '10'), ('11', '11'), ('12', '12'), ('13', '13'), ('14', '14'), ('15', '15'), ('16', '16'), ('17', '17'), ('18', '18'), ('19', '19'), ('20', '20'), ('21', '21'), ('22', '22'), ('23', '23'), ('24', '24'), ('25', '25'), ('26', '26'), ('27', '27'), ('28', '28'), ('29', '29'), ('30', '30'), ('31', '31'), ('32', '32'), ('33', '33'), ('34', '34'), ('35', '35'), ('36', '36'), ('37', '37'), ('38', '38'), ('39', '39'), ('40', '40'), ('41', '41'), ('42', '42'), ('43', '43'), ('44', '44'), ('45', '45'), ('46', '46'), ('47', '47'), ('48', '48'), ('49', '49'), ('50', '50'), ('51', '51'), ('52', '52'), ('53', '53'), ('54', '54'), ('55', '55'), ('56', '56'), ('57', '57'), ('58', '58'), ('59', '59'), ('60', '60'), ('61', '61'), ('62', '62'), ('63', '63'), ('64', '64'), ('65', '65'), ('66', '66'), ('67', '67'), ('68', '68'), ('69', '69'), ('70', '70'), ('71', '71'), ('72', '72'), ('73', '73'), ('74', '74'), ('75', '75'), ('76', '76'), ('77', '77'), ('78', '78'), ('79', '79'), ('80', '80'), ('81', '81'), ('82', '82'), ('83', '83'), ('84', '84'), ('85', '85'), ('86', '86'), ('87', '87'), ('88', '88'), ('89', '89'), ('90', '90'), ('91', '91'), ('92', '92'), ('93', '93'), ('94', '94'), ('95', '95'), ('96', '96'), ('97', '97'), ('98', '98'), ('99', '99')])
class EditUserForm(Form):
    choice = RadioField(None, choices=[("reset", "Reset User Password"), ("delete", "Delete User")])

#Pages
@app.route('/', methods=['GET', 'POST'])
def index():
	if session.get('logged_in'):
		class CForm(CardForm):
				expiration=Expiration.query.get(1)
				expmon=IntegerField('Expiry Month', validators=[DataRequired(), NumberRange(min=1, max=12, message="Value must be between 1 and 12")])
				expyear=IntegerField('Expiry Year', validators=[DataRequired(), NumberRange(min=expiration.start, max=expiration.end, message="Value must be between {0} and {1}".format(expiration.start, expiration.end))])
		form, error = CForm(), None
		if form.validate_on_submit():
			cardnumber="{0}{1}{2}{3}".format(form.pana.data, form.panb.data, form.panc.data, form.pand.data)
			expiredate="{0}/{1}".format(form.expmon.data, form.expyear.data)
			aesc = aescrypt(StringIO.StringIO(Users.query.get(1).password).read(32)) #ridiculously arbritary but only way to reasonably encrypt data.
			card = Cards(name=aesc.encrypt(form.name.data), cvc=aesc.encrypt(form.CV2.data), cardNumber=aesc.encrypt(cardnumber), expireDate=aesc.encrypt(expiredate), clientReference=aesc.encrypt(form.reference.data), amount=aesc.encrypt(form.amount.data), user=aesc.encrypt(session.get('username')))
			db.session.add(card)
			db.session.commit()
			return redirect(url_for('index'))
		else: 
			error=error
		return render_template('index.html', form=form, error=error)
	elif not session.get('logged_in'):
		form, error = LoginForm(), None
		if form.validate_on_submit():
			user=Users.query.filter_by(username=form.username.data).first()
			try:
				if Auth(user.username).verify(user.password, form.password.data):
					session["logged_in"]=True
					session["username"]=user.username
					if user.reset == 1:
					    flash("Your password was reset. Please ensure you change it to a memorable password.")
					    return redirect(url_for('pword'))
					else:
					    return redirect(url_for('index'))
				else:
					error="Username or password is incorrect."
			except:
				error="Username not found."
		else:
			error=error
		return render_template('login.html', form=form, error=error)
	else:
		abort(401)
@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
	if session.get('logged_in') and session.get('username')=='admin':
		form, error = NewUser(), None
		if form.validate_on_submit():
			user = Users.query.filter_by(username=form.username.data).first()
			if not user:
				user = Users(username=form.username.data, password=Auth(form.username.data).hash(form.password.data), reset=1)
				db.session.add(user)
				db.session.commit()
				flash("Successfully created user {0}".format(user.username))
			else:
				error="User already exists"
		return render_template('createuser.html', form=form, error=error)
	else:
		abort(401)
@app.route('/list')
def list():
	row2dict = lambda r: {c.name: str(getattr(r, c.name)) for c in r.__table__.columns}
	cards = Cards.query.all()
	aesc = aescrypt(StringIO.StringIO(Users.query.get(1).password).read(32)) #ridiculously arbritary but only way to reasonably encrypt data.
	cardds=[]
	for card in cards:
		cardd=row2dict(card)
		keys =[]
		for key in cardd.keys():
			if key == "id":
				pass
			else:
				keys.append(key)
		a=[]
		for key in keys:
			a.append(aesc.decrypt(cardd[key]))
		cardds.append(a)
	return render_template('list.html', cards=cardds)

@app.route('/create')
def create():
	row2dict = lambda r: {c.name: str(getattr(r, c.name)) for c in r.__table__.columns}
	cards = Cards.query.all()
	aesc = aescrypt(StringIO.StringIO(Users.query.get(1).password).read(32)) #ridiculously arbritary but only way to reasonably encrypt data.
	pw = Password.query.get(1).password
	pword = aesc.decrypt(pw)
	references=[]
	files = glob.glob('./zips/*')
	for f in files:
		os.remove(f)
	files = glob.glob('./*.csv')
	for f in files:
		os.remove(f)
	for card in cards:
		cardd=row2dict(card)
		reference = ''.join(st for st in aesc.decrypt(cardd['clientReference']) if st.isalnum())
		with open("{0}.csv".format(reference), 'wb') as f:
			keys =[]
			for key in cardd.keys():
				if key == "id" or key == "user":
					pass
				else:
					keys.append(key)
			w = csv.writer(f)
			w.writerow(keys)
			a=[]
			for key in keys:
				a.append(aesc.decrypt(cardd[key]))
			w.writerow(a)
		os.system('7z a -p{0} "./zips/{1}.zip" "{2}.csv"'.format(pword, reference, reference))
		references.append(reference)
		db.session.delete(card)
	files = glob.glob('./*.csv')
	for f in files:
		os.remove(f)
	db.session.commit()
	return render_template('key.html', references=references)

@app.route('/changepassword', methods=['get', 'post'])
def change():
	if session.get('logged_in'):
		form, error = PassForm(), None
		if form.validate_on_submit():
			aesc = aescrypt(StringIO.StringIO(Users.query.get(1).password).read(32)) #ridiculously arbritary but only way to reasonably encrypt data.
			pword=Password.query.get(1)
			pword.password=aesc.encrypt(form.password.data)
			db.session.commit()
			return redirect(url_for('index'))
		else:
			error=error
		return render_template('change.html', form=form, error=error)
	else:
		abort(401)
@app.route('/changelogin', methods=['get','post'])
def pword():
	if session.get('logged_in'):
		form, error = ChangeForm(), None
		if form.validate_on_submit():
			user = Users.query.filter_by(username=session.get('username')).first()
			a = Auth(user.username)
			if a.verify(user.password, form.current.data):
				user.password=a.hash(form.new.data)
			db.session.commit()
			flash("Password successfully changed")
		else:
			error=error
		return render_template('changelogin.html', form=form, error=error)
	else:
		abort(401)
@app.route('/date', methods=['GET', 'POST'])
def date():
	if session.get('logged_in') and session.get('username')=="admin":
		form, error = ExpirationForm(), None
		if form.validate_on_submit():
			expiration=Expiration.query.get(1)
			expiration.start = form.start.data
			expiration.end = form.end.data
			db.session.commit()
			flash("Validation dates successfully changed.")
		else:
			error=error
		return render_template('changedate.html', form=form, error=error)
	else:
		abort(401)
@app.route('/list_users')
def list_users():
    users = Users.query.all()
    user_list = []
    for user in users:
        temp_dict = {'username':user.username, 'id':user.id}
        user_list.append(temp_dict)
    if session.get('username')=='admin':
        return render_template("userlist.html", user_list=user_list)
    else:
        abort(401)
    
@app.route('/user/<string:user_id>', methods=['get', 'post'])
def edit_user(user_id):
    if session.get('username')=='admin':
        user = Users.query.get(int(user_id))
        form, error = EditUserForm(), None
        if form.validate_on_submit():
            if form.choice.data== "delete":
                db.session.delete(user)
                db.session.commit()
                flash("User {0} was deleted".format(user.username))
                return redirect(url_for('list_users'))
            elif form.choice.data == "reset":
                user.password = Auth(user.username).hash("password")
                user.reset = 1
                db.session.commit()
                flash("User {0}'s password was reset to 'password', they will be directed to change their password on login.".format(user.username))
                return redirect(url_for('list_users'))
            else:
                error="You must choose to delete the user or reset their password."
        else:
            error=error
        return render_template('edituser.html', user_id=user_id, form=form, error=error)
        
    
@app.route('/logout')
def logout():
	session.pop('logged_in')
	session.pop('username')
	flash("You were logged out")
	return redirect(url_for("index"))

if __name__ == '__main__':
	app.run(host='0.0.0.0')