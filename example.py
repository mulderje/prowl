"""
Example notification using prowl.
"""
import prowlpy

apikey = '1234567890123456789012345678901234567890' #Dummy API-key)
try:
	p = prowlpy.Api(apikey)
	n = prowlpy.Notification('TestApp', 'Server Down', "The Web Box isn't responding to a ping")
	p.post(n)
	print 'Success'
except Exception,msg:
    print msg