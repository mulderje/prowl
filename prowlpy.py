# -*- coding: utf-8 -*-
# Copyright (c) 2009 Jonathan Mulder <mulderje@muohio.edu>
# 					 Jacob Burch <jacobburch@gmail.com>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

'''
Prowlpy v0.5.3

Written by Jacob Burch, 7/6/2009
		   Jonathan Mulder, 7/18/2009

Python module for posting to the iPhone Push Notification service Prowl Api: http://prowl.weks.net/
'''
__author__ = 'jacobburch@gmail.com, mulderje@muohio.edu'
__version__ = '0.5.3'

import httplib2
import urllib

API_DOMAIN = 'https://prowl.weks.net/publicapi'

class Api(object):
	'''A python interface to the prowler Api
	
	Example usage:
		To create an instance of the prowlpy.Api class:
		
			>>> import prowlpy
			>>> api = prowlpy.Api('1234567890123456789012345678901234567890')
		
		To verity the validity of an api key:
			
			>>> api.verify()
			
		To post a notification:
		
			Create a Notification instance (n)
			>>> api.post(n)
			
		Both the verify and the post methods will return success or failure values.
	'''
	def __init__(self,
				 apikey=None,
				 providerkey=None):
		'''An object to hold a Prowler api instance
		
		Args:
		   apikey: The user's API key. A 40-byte hexadecimal string.
		   providerkey: Your provider API key. Only necessary if you have been whitelisted.
		'''
		self.apikey = apikey
		self.providerkey = providerkey
		
		# Aliasing
		self.add = self.post

	def get_apikey(self):
		'''Get the api key for the prowler instance.
		
		Returns:
			The apikey for the prowler instance
		'''
		return self._apikey
	
	def set_apikey(self, apikey):
		'''Set the api key for the prowler instance.
		
		Args:
		   apikey: The apikey for the prowler instance
		'''
		if not len(apikey) == 40:
			raise ValueError('apikey must be 40 bytes in length')
		self._apikey = apikey
	
	apikey = property(get_apikey, set_apikey,
						doc='The api key for the prowler instance.')
	
	def get_providerkey(self):
		'''Get the provider key for the prowler instance.
		
		Returns:
			The providerkey for the prowler instance
		'''
		return self._providerkey
	
	def set_providerkey(self, providerkey):
		'''Set the provider key for the prowler instance.
		
		Args:
		   apikey: The apikey for the prowler instance
		'''
		if providerkey is not None and not len(providerkey) == 40:
			raise ValueError('providerkey must be 40 bytes in length')
		self._providerkey = providerkey
	
	providerkey = property(get_providerkey, set_providerkey,
						doc='The provider key for the prowler instance.')
						
	def verify(self):
		'''Verify an API key is valid.
		
		TODO:
			Add support for providerkey still...
			Add more robust error checking
		
		Returns:
			True: Returns true if the response is 200
		Exception:
			If anything fails
		'''
		h = httplib2.Http()
		headers = {'User-Agent': "Prowlpy/%s" % str(__version__)}
		verify_resp,verify_content = h.request("%s/verify?apikey=%s" % \
												(API_DOMAIN,self.apikey))
		if verify_resp['status'] != '200':
			raise Exception("Invalid API Key %s" % verify_content)
		else:
			return True
			
	def post(self,
			 notification):
		'''Post a notification using the given api key.
		
		TODO:
			Create more robust error checking
		
		Args:
			notification: A notification object
			
		Returns:
			True: Returns true if the response is 200
		Exception:
			401: if authentification fails
			Else: if anything else happens
		'''
        # Create the http object
		h = httplib2.Http()

        # Set User-Agent
		headers = {'User-Agent': "Prowlpy/%s" % str(__version__)}

        # Perform the request and get the response headers and content
		data = {
			'apikey': self.apikey,
			'application': notification.application,
			'event': notification.event,
			'description': notification.description,
			'priority': notification.priority
		}
		headers["Content-type"] = 'application/x-www-form-urlencoded'
		resp,content = h.request("%s/add/" % API_DOMAIN, "POST", headers=headers, body=urllib.urlencode(data))

		if resp['status'] == '200':
			return True
		elif resp['status'] == '401':
			raise Exception("Auth Failed: %s" % content)
		else:
			raise Exception('Failed')

class Notification(object):
	'''A python interface for a growl Notification to be sent through the prowler Api
	
	Example usage:
		To send a Notification:
		
			Create an Api instance (api)
			>>> import prowlpy
			>>> n = prowlpy.Notification('TestApp', 'Server Down', "The Web Box isn't responding to a ping")
			>>> api.post(n)	
	'''
	def __init__(self,
				 application=None,
				 event=None,
				 description=None,
				 priority=0):
		'''An object to hold a Prowler notification.
		
		Args:
		   application: The name of your application or the application generating the event.
		   event: The name of the event or subject of the event.
		   description: A description of the event, generally terse.
		   priority: An integer value ranging [-2, 2]: Very Low, Moderate, Normal, High, Emergency.
		'''
		self.application = application
		self.event = event
		self.description = description
		self.priority = priority
		
	def get_application(self):
		'''Get the application for the notification
		
		Returns:
			The application for the notification
		'''
		return self._application
		
	def set_application(self, application):
		'''Sets the application for the notification
		
		Args:
			event: The application for the notification
		'''
		if not len(application) <= 256:
			raise ValueError('events application must be <= 256')
		self._application = unicode(application)
		
	application = property(get_application, set_application,
							doc='The application for the notification.')
							
	def get_event(self):
		'''Get the event for the notification

		Returns:
			The event for the notification
		'''
		return self._event

	def set_event(self, event):
		'''Sets the event for the notification

		Args:
			event: The event for the notification
		'''
		if not len(event) <= 1024:
			raise ValueError('events length must be <= 1024')
		self._event = unicode(event)

	event = property(get_event, set_event,
							doc='The event for the notification.')
							
	def get_description(self):
		'''Get the description for the notification

		Returns:
			The description for the notification
		'''
		return self._description

	def set_description(self, description):
		'''Sets the description for the notification

		Args:
			description: The description for the notification
		'''
		if not len(description) <= 10000:
			raise ValueError('description length must be <= 10000')
		self._description = unicode(description)

	description = property(get_description, set_description,
							doc='The description for the notification.')

	def get_priority(self):
		'''Get the priority for the notification.

		Returns:
			The priority for the notification
		'''
		return self._priority

	def set_priority(self, priority):
		'''Sets the priority for the notification.

		Args:
			priority: The priority for the notification
		'''
		if not (priority >= -2 or priority <= 2):
			raise ValueError('priority must be in the range [-2, 2]')
		self._priority = priority

	priority = property(get_priority, set_priority,
						doc='The priority for the notification.')

