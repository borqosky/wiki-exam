import webapp2
import jinja2
import os, re
import hmac, hashlib

from google.appengine.ext import db

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENVIROMENT = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
							   extensions=['jinja2.ext.autoescape'])
SECRET = open('password.cfg').read()
COOKIE_RE = re.compile(r'^user_id=$')


################Cookies################
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

################Password###############

class BaseHandler(webapp2.RequestHandler):
	def __render_str(self, template, **kwargs):
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


class MainPage(BaseHandler):
	def get(self):
		template_values = {
			'view': 'view',
			'history': 'history',
			'action': 'action',
			'user_log': 'user_log',
			'user_sig': 'user_sig',
		}
		self.render('base.html', template_values)


application = webapp2.WSGIApplication([
	('/', MainPage),
], debug=True)