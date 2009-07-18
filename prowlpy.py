# -*- coding: utf-8 -*-
'''
Prowlpy v0.5.2

Written by Jacob Burch, 7/6/2009
		   Jonathan Mulder, 7/18/2009

Python module for posting to the iPhone Push Notification service Prowl: http://prowl.weks.net/
'''
__author__ = 'jacobburch@gmail.com, mulderje@muohio.edu'
__version__ = 0.52

import httplib2
import urllib

API_DOMAIN = 'https://prowl.weks.net/publicapi'

class Api(object):
	'''A python interface to the prowler api
	
	Example usage:
		To create an instance of the prowlpy.Api class:
		
			>>> import prowlpy
			>>> api = prowlpy.Api('1234567890123456789012345678901234567890')
		
		To verity the validity of an api key:
			
			>>> api.verify()
			
		To post a notification:
		
			Create a notification object (n)
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
	'''A python interface for a growl notification to be sent through the prowler api
	
	Example usage:
		To send a notification:
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
		   priority: An integer value ranging [-2, 2]: Very Low, Moderate, Normal, High, Emergency.
		   application: The name of your application or the application generating the event.
		   event: The name of the event or subject of the event.
		   description: A description of the event, generally terse.
		'''
		self.priority = priority
		self.application = application
		self.event = event
		self.description = description
		
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
			self._priority = prioriy
			
		priority = property(get_priority, set_priority,
							doc='The priority for the notification')
							
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
								doc='The event for the notification')
								
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
								doc='The event for the notification')
								
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
								doc='The description for the notification')
