import webapp2
import jinja2
import os

from google.appengine.ext import db

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENVIROMENT = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
							   extensions=['jinja2.ext.autoescape'])

class MainPage(webapp2.RequestHandler):
	def get(self):

		template = JINJA_ENVIROMENT.get_template('base.html')
		template_values = {
			'view': 'view',
			'history': 'history',
			'action': 'action',
			'user_log': 'user_log',
			'user_sig': 'user_sig',
		}
		self.response.write(template.render(template_values))


application = webapp2.WSGIApplication([
	('/', MainPage),
], debug=True)