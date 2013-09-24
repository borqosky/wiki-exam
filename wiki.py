import webapp2
import jinja2
import os, re, string
import hmac, hashlib
import logging
import random

from google.appengine.ext import db

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENVIROMENT = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
							   extensions=['jinja2.ext.autoescape'])
SECRET = open('password.cfg').read()
COOKIE_RE = re.compile(r'^user_id=$')


################Cookies###########################

def hash_str(s):
	return hmac.new(SECRET, str(s)).hexdigest()

def make_secure_val(s):
	return '%s|%s' % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

def valid_cookie(cookie):
	return cookie and COOKIE_RE.match(cookie)

################Password##########################

def make_salt(length=5):
	return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
	salt = h.split(',')[1]
	return h == self.make_pw_hash(name, pw, salt)

################Models#############################

class User(db.Model):
	username = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required=True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return cls.get_by_id(uid)

	@classmethod
	def by_name(cls, name):
		return cls.all().filter('name = ', name).get()

	@classmethod
	def register(cls, name, pw, email=None):
		pw_hash = make_pw_hash(name, pw)
		return User(username=name, pw_hash=pw_hash, email=email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u


class Article(db.Model):
	subject = db.StringProperty(required=True)
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now=True)

	def render(self):
		t = JINJA_ENVIROMENT.get_template('view.html')
		return t.render(a=self)

################base##############################

class BaseHandler(webapp2.RequestHandler):
	def __render_str(self, template, **params):
		t = JINJA_ENVIROMENT.get_template(template)
		return t.render(params)

	def initialize(self, *args, **kwargs):
		webapp2.RequestHandler.initialize(self, *args, **kwargs)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

	def write(self, *args, **kwargs):
		self.response.write(*args, **kwargs)

	def render(self, template, **kwargs):
		self.write(self.__render_str(template, **kwargs))

	def set_secure_cookie(self, name, val):
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, make_secure_val(val)))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return valid_cookie(cookie_val) and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

################wiki##############################

USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
def valid_username(username):
	return USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return EMAIL_RE.match(email)


class SignupPage(BaseHandler):
	def get(self):
		self.render('signup.html')
	
	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username=self.username, email=self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True
		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		if self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True
		if self.email and not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup.html', **params)
		else:
			self.done()

	def done(self):
		# make sure the user doesn't already exist
		u = User.by_name(self.username)
		if u:
			msg = 'That user already exists.'
			self.render('signup.html', error_username=msg)
			u = User.register(self.name, self.password, self.email)
			u.put()
			self.login()
			self.redirect('/')

class LoginPage(BaseHandler):
	def get(self):
		pass
	
	def post(self):
		pass


class ViewPage(BaseHandler):
	def get(self, article):
		pass


class EditPage(BaseHandler):
	def get(self, article):
		self.write(article)

	def post(self):
		pass


application = webapp2.WSGIApplication([
	('/signup/?', SignupPage),
	('/login', LoginPage),
	('/_edit/(.*)/?', EditPage),
	('/(.*)/?', ViewPage),
], debug=True)