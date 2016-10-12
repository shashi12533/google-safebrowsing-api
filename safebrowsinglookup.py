""" Version 0.2.0
Google Safe Browsing Lookup library for Python.
"""
import re
import requests
import json

class SafebrowsinglookupClient(object):
    def __init__(self, key='', debug=1, error=0):
        """ Create a new client. You must pass your Google API key (http://code.google.com/apis/safebrowsing/key_signup.html).
            Arguments:
                key: API key.
                debug: Set to 1 to print debug & error output to the standard output. 0 (disabled) by default.
                error: Set to 1 to print error output to the standard output. 0 (disabled) by default.
        """
        self.key = 'AIzaSyDK6GKTFlsMqme9BP7LyvBe3XgjV5MUcMg'
        self.debug = debug
        self.error = error
        self.last_error = ''
        self.version = '1.5.2'
        self.api_version = '3.1'
        self.url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?'

        if self.key == '':
            raise ValueError("Missing API key")

    def lookup(self, *urls):
        results = []
        count = 0
        while count * 500 < len(urls):
            inputs = urls[count * 500 : (count + 1) * 500]
            url_list = []
            for url in inputs:
                url_list.append(self.__canonical(str(url)))
            print(url_list)
            post_fields = {}
            client_data = { 'clientId' : 'test', "clientVersion": "1.5.2" }
            post_fields['client'] = client_data
            threat_data = { "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING"],
                            "platformTypes":    ["WINDOWS", "LINUX"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries" : []
                          }
            post_url = '{0}&key={1}'.format(self.url, self.key)
            print("URL: %s" % (post_url))
            for url in url_list:
                threat_data['threatEntries'].append({'url': url})
            post_fields['threatInfo'] = threat_data
            
            print post_fields
            response = ''
            try:
                response = requests.post(post_url, json=post_fields)
                print response.text

            except Exception, e:
                if hasattr(e, 'code') and e.code == httplib.NO_CONTENT: # 204
                    self.__debug("No match\n")
                    results.append( self.__ok(inputs) )

                elif hasattr(e, 'code') and e.code == httplib.BAD_REQUEST: # 400
                    self.__error("Invalid request")
                    results.append( self.__errors(inputs) )

                elif hasattr(e, 'code') and e.code == httplib.UNAUTHORIZED: # 401
                    self.__error("Invalid API key")
                    results.append( self.__errors(inputs) )

                elif hasattr(e, 'code') and e.code == httplib.FORBIDDEN: # 403 (should be 401)
                    self.__error("Invalid API key")
                    results.append( self.__errors(inputs) )

                elif hasattr(e, 'code') and e.code == httplib.SERVICE_UNAVAILABLE: # 503
                    self.__error("Server error, client may have sent too many requests")
                    results.append( self.__errors(inputs) )

                else:
                    self.__error("Unexpected server response")
                    self.__debug(e)
                    results.append( self.__errors(inputs) )
            else:
                print response.status_code
                response_data = response.text
                if not response_data:
                    self.__debug("No match\n")
                    results.append( self.__ok(inputs) )
                else:
                    self.__debug("At least 1 match\n")
                    url_string = ''
                    response_data = response_data.strip()
                    response_data = json.loads(response_data)
                    if response_data and response_data['matches']:
                        response_url_list =  response_data['matches']
                        url_list = []
                        for x in response_url_list:
                            url_list.append(x['threat']['url'])
                        print url_list

                        url_string = '\n'.join(url_list)
                        print url_string
                    results =  self.__parse(url_string, inputs)     
            
            count = count + 1
        print results
        return results

    # Private methods

    # Not much is actually done, full URL canonicalization is not required with the Lookup library according to the API documentation
    
    def __canonical(self, url=''):
        url = url.strip()    # remove leading/ending white spaces
        # Remove any embedded tabs and CR/LF characters which aren't escaped.
        url = url.replace('\t', '').replace('\r', '').replace('\n', '')
        scheme = re.compile("https?\:\/\/", re.IGNORECASE)# make sure whe have a scheme
        if scheme.match(url) is None:
            url = "http://" + url
        return url

    def __parse(self, response, urls):
        lines = response.splitlines()

        if (len(urls) != len(lines)):
            self.__error("Number of URLs in the response does not match the number of URLs in the request");
            self.__debug( str(len(urls)) + " / " + str(len(lines)) )
            self.__debug(response);
            return self.__errors(lines);

        results = []
        for i in range(0, len(lines)):
            results.append({urls[i] : lines[i]})

        return results

    def __errors(self, urls):
        results = []
        for url in urls:
            results.append({url: 'error'})

        return results

    def __ok(self, urls):
        results = []
        for url in urls:
            results.append({url: 'ok'})

        return results

    def __debug(self, message=''):
        if self.debug == 1:
            print message

    def __error(self, message=''):
        if self.debug == 1 or self.error == 1:
            print message + "\n"
            self.last_error = message

if __name__=="__main__":
    obj = SafebrowsinglookupClient()
    res = obj.lookup('http://ianfette.org/','http://ianfette.org/','http://www.urltocheck3.com/')

    
    
    #             {
#    "client": {
#      "clientId":      "test",
#      "clientVersion": "1.5.2"
#    },
#    "threatInfo": {
#      "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING"],
#      "platformTypes":    ["WINDOWS", "LINUX"],
#      "threatEntryTypes": ["URL"],
#      "threatEntries": [
#        {"url": "http://ianfette.org/"},
#        {"url": "http://www.ianfette.org/"},
#        {"url": "http://www.urltocheck3.com/"}
#      ]
#    }
#  }

#{'client':
# {'clientVersion': '1.5.2', 'clientId': 'test'},
# 'threatInfo': 
# {'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'], 
#  'threatEntries': [{'url': 'http://ianfette.org/'}, {'url': 'http://ianfette.org/'}, {'url': 'http://ianfette.org/'}], 
#  'platformTypes': ['WINDOWS', 'LINUX'], 
#  'threatEntryTypes': ['URL']
# }
#}
