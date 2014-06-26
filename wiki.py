import webapp2
import jinja2
import os, re, string
import hmac, hashlib
import logging
import random

from google.appengine.ext import db
from google.appengine.api import memcache

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENVIROMENT = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
							   extensions=['jinja2.ext.autoescape'])
SECRET = open('password.cfg').read()
COOKIE_RE = lambda cookie: '|' in cookie


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
	return cookie and COOKIE_RE(cookie)


################memcache##########################

def get_page(update=False, key=None):
	page = memcache.get(key)
	if not page or update:
		logging.error('DB QUERY')
		page = Page.by_name(key)
		if page: memcache.set(key, page)
	return page


####################css###########################

def gray_style(lst):
	for n, x in enumerate(lst):
		if n % 2 == 0:
			yield x, ''
		else:
			yield x, 'gray'

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
	return h == make_pw_hash(name, pw, salt)

################Models#############################

class User(db.Model):
	username = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required=True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid)

	@classmethod
	def by_name(cls, name):
		return User.all().filter('username =', name).get()

	@classmethod
	def register(cls, name, pw, email=None):
		pw_hash = make_pw_hash(name, pw)
		return User(username=name, pw_hash=pw_hash, email=email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u


class Page(db.Model):
	title = db.StringProperty()
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	version = db.IntegerProperty(required=True)
	last_modified = db.DateTimeProperty(auto_now=True)

	@staticmethod
	def parent_key(path):
		return db.Key.from_path('/root' + path, 'pages')

	@classmethod
	def by_path(cls, path):
		q = cls.all()
		q.ancestor(cls.parent_key(path))
		q.order('-created')
		return q

	@classmethod
	def by_id(cls, page_id, path):
		return cls.get_by_id(page_id, cls.parent_key(path))

	@classmethod
	def by_name(cls, name):
		return Page.all().filter('title =', name).order('-created')

################base##############################


class BaseHandler(webapp2.RequestHandler):
	def __render_str(self, template, **params):
		t = JINJA_ENVIROMENT.get_template(template)
		return t.render(params)

	def initialize(self, *args, **kwargs):
		webapp2.RequestHandler.initialize(self, *args, **kwargs)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))
		self.previous_page = self.request.headers.get('referrer', '/')
		self.can_post = self.user and self.user.username == 'wlodek'

	def write(self, *args, **kwargs):
		self.response.write(*args, **kwargs)

	def render(self, template, **kwargs):
		self.write(self.__render_str(template, **kwargs))

	def render_str(self, template, **params):
		params['user'] = self.user
		params['gray_style'] = gray_style
		return render_str(template, **params)

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

	def notfound(self):
		self.error(404)
		self.write("<h1>404: Not Found</h1>Sorry, my friend, but that page does not exist.")	


class NoSlash(BaseHandler):
	def get(self, path):
		new_path = path.rstrip('/') or '/'
		self.redirect(new_path)


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


class Signup(BaseHandler):
	def get(self):
		self.render('signup.html', previous_page=self.previous_page)
	
	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')
		if not self.previous_page or self.previous_page.startswith('/login'):
			self.previous_page = '/'

		params = dict(username=self.username, email=self.email, previous_page=self.previous_page)

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
			self.render('signup.html', error_username=msg, 
				                       previous_page=self.previous_page)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()
			self.login(u)
			
			if self.previous_page == '/login':
				self.redirect('/')
			else:
				self.redirect(self.previous_page)


class Login(BaseHandler):
	def get(self):
		self.render('login.html', previous_page=self.previous_page)
	
	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		if not self.previous_page or self.previous_page.startswith('/login'):
			self.previous_page = '/'

		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect(self.previous_page)
		else:
			msg = 'Invalid login'
			self.render('login.html', error=msg, 
				                      previous_page=self.previous_page)


class Logout(BaseHandler):
	def get(self):
		self.logout()
		self.redirect(self.previous_page)


class WikiPage(BaseHandler):
	def get(self, path):
		v = self.request.get('v')
		p = None
		if v:
			if v.isdigit():
				p = Page.by_id(int(v), path)
			if not p:
				return self.notfound()
		else:
			p = Page.by_name(path).get()

		if p:
			self.render('wiki_page.html', page=p, path=path, 
										  edit=True, user=self.user)
		else:
			self.redirect("/_edit" + path)


class EditPage(BaseHandler):
	def get(self, path):
		if not self.user:
			self.redirect('/login')

		v = self.request.get('v')
		p = None
		if v:
			if v.isdigit():
				p = Page.by_id(int(v), path)
			if not p:
				return self.notfound()
		else:
			p = Page.by_name(path).get()

		self.render('edit.html', edit=False, page=p, path=path, 
			                     user=self.user, title=path)

	def post(self, path):
		if not self.user:
			self.error(400)
			return

		content = self.request.get('content').strip()
		old_page = Page.by_path(path).get()
		version = 0
		if old_page:
			version = old_page.version + 1
		# what to do when empty content is submitted ?
		if not (old_page or content):
			return
		elif not old_page or old_page.content != content:
			path = path.replace('_edit', '')
			p = Page(parent=Page.parent_key(path), content=content, 
				     title=path, version=version)
			p.put()
		#p = get_page(update=True, key=path)
		self.redirect(path)


class HistoryPage(BaseHandler):
	def get(self, path):
		if path == None:
			path = '/'
		q = db.GqlQuery("SELECT * FROM Page WHERE title = '%s'" % path)
		posts = list(q)
		if posts:
			self.render('history.html', versions=posts)
		else:
			self.redirect('/_edit' + path)


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

application = webapp2.WSGIApplication([
	('/signup', Signup),
	('/login', Login),
	('/logout', Logout),
	('/_history' + PAGE_RE, HistoryPage),
	('/_edit' + PAGE_RE, EditPage),
	(PAGE_RE, WikiPage),
], debug=True)
