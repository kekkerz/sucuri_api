import requests, re, json
from bs4 import BeautifulSoup as bs #HTML Parser used to check for existing tickets

class sucuri:

	def __init__(self, config):
		self.config = config
		self.key = self.config['sucuri_api_key']
		self.sucuri_url = self.config['sucuri_url']

	def get_token(self, session): #Get token necessary for making certain POST requests
		r = session.get('https://monitor9.sucuri.net/monitor/').text
		token = re.search('(?<=sucuritoken\" value=\")[a-zA-Z0-9]+', r).group(0)

		return token

	def login(self): #Begin login session
		with requests.Session() as session:
			login_form = session.get('https://login.sucuri.net/login/?loggedout').text
			#This token is separate from self.token and will always be different. This token is only required to complete the login
			token = re.search('(?<=sucuritoken\" value=\")[a-zA-Z0-9]+', login_form).group(0)
			payload = {'email1':self.config['sucuri_email'], 'passw1':self.config['sucuri_pass'], 'sucuritoken':token, 'doLogin':'Login'}

			r = session.post('https://login.sucuri.net/login/?loggedout', data=payload).status_code

			if r == 200: #Return session object if login was successful
				return session

	def add_site(self, domain): #Add site to Sucuri
		if not self.grep_domain(domain): #Check if site already exists on Sucuri
			result = requests.get('{}{}&a=add&host={}'.format(self.sucuri_url, self.key, domain)).text
			return result
		else:
			return '{} has already been added to sucuri'.format(domain)

	def del_site(self, odomain):
		domain = self.grep_domain(odomain)
		if domain:
			result = requests.get('{}{}&a=delete&host={}'.format(self.sucuri_url, self.key, domain)).text
			return result
		else:
			return '{} has not yet been added to Sucuri'.format(odomain)

	def grep_domain(self, domain): #Query list of available domains from Sucuri, and check if provided domain is listed
		result = requests.get('{}{}&a=list'.format(self.sucuri_url, self.key)).text
		try:
			full_dom = [line for line in result.split("\n") if domain in line][0].split(",")[0]
			return full_dom
		except IndexError:
			return False

	def run_scan(self, domain): #Force Sucuri to run a new scan on the provided domain
		self.session = self.login() #Setup login session and get token
		self.token = self.get_token(self.session)
		f = self.grep_domain(domain) #Get formatted domain to be used in POST request

		if f: #Ensure domain exists in Sucuri
			payload = {'sucuritoken':self.token, 'host':domain, 'f':f, 'resource':'Run WWW Check'}
			r = self.session.post('https://monitor9.sucuri.net/monitor/?site={}'.format(domain), data=payload)

			if r.status_code == 200: #Sucuri returns HTML for this rather than json, so we have to assume a 200 means success
				return 'Scan started for {}'.format(domain)
		else:
			return '{} does not exist in Sucuri.'.format(domain)

	def query(self, domain): #Query scan results from sucuri
		full_dom = self.grep_domain(domain)

		if not full_dom: #Checks if grep_domain was un-successful
			print('Domain not added to Sucuri')
			raise SystemExit(0)

		#Send GET request to Sucuri for scan results
		result = requests.get('{}{}&a=query&host={}'.format(self.sucuri_url, self.key, full_dom)).text

		if "MALWARE: WARN:" in result: #Take action based on scan results
			if 'Site error detected' in result or 'Index page missing' in result:
				return {
					'result':'Site error detected on {}'.format(domain),
					'status':'Error',
					'query':result,
				}
			else:
				return {
					'result':'Possible malware for {}'.format(domain),
					'status':'Malware',
					'query':result,
				}
		elif 'OUTDATEDSCAN:' in result and re.search('OUTDATEDSCAN:[a-zA-Z0-9\ \_\:\-]+ Found', result):
			return {
				'result':'Outdated software on {}'.format(domain),
				'status':'Outdated',
				'query':result,
			}
		elif "SYSTEM: ERROR:" in result:
			return {
				'result':'Site error deteceted on {}'.format(domain),
				'status':'Error',
				'query':result,
			}
		else:
			return {
				'result':'{} appears to be clean'.format(domain),
				'status':'Clean',
				'query':result,
			}

	def ticket_exists(self, domain): #Check if a ticket currently exists for provided domain
		self.session = self.login()
		self.token = self.get_token(self.session)
		#There's no API for this, so we must parse the HTML for the information we need
		soup = bs(self.session.get('https://support.sucuri.net/support/').text, "html5lib")
		#This get's the full list of tickets
		ticket_list = bs(soup.find_all('div')[7].prettify(), "html5lib")

		for i in ticket_list.find_all('a'): #Loop over tickets and find "unread" or "waiting" tickets, and check them for the provided domain
			if re.search(domain, str(i)) and ("class=\"unread" in str(i) or "class=\"waiting" in str(i)):
				ticket_id = re.search('(?<=Ticket ID: ).*', str(i)).group(0)
				return ticket_id

	def create_ticket(self, domain, host, username, password): #Create malware removal request to Sucuri
		self.session = self.login()
		self.token = self.get_token(self.session)
		ticket_id = self.ticket_exists(domain)

		if host is None or username is None or password is None: #Ensure the correct paramaters were passed
			raise TypeError

		if not ticket_id: #Checks if ticket_id is empty. If this is the case, there is no existing ticket
			payload = {'infectedsite':domain, 'tags%5B%5D':'mlw-alert-sucuri', 'connectiontype':'FTP', 'hostname':host, 'port':'21', 'username':username,
				'password':password, 'directory':'', 'sucuritoken':self.token, 'force':'1', 'desc':'4'}
			r = self.session.post('https://support.sucuri.net/support//ajax/newmalwareticket/', data=payload)
			result = json.loads(r.text)

			if 'Successfully created' in result['message']: #Check if ticket creation was successful 
				print('Ticket created successfully! https://support.sucuri.net/support/ticket/{}'.format(result['id']))
			else:
				print(result['message'])
		else:
			print('Ticket already exists. Ticket ID: {}'.format(ticket_id))