global config
global whitelist

#Configuration data for grove login, and sucuri API calls
config = {
	'username':'', # Grove Username
	'password':'', # Grove Password
	'sucuri_api_key':'', #Sucuri API key
	'sucuri_url':'https://monitor9.sucuri.net/api.php?k=', #Sucuri API URL
	'sucuri_email':'',
	'sucuri_pass':'',
	'synco_user':'',
	'synco_passwd':'',
	'whmcs_user':'',
	'whmcs_passwd':'',
	'helix_user':'',
	'helix_passwd':'',
}

#Add entry to this list if customer does not want to receive updates regarding outdated software
#Supports domains and emails
#Add entry to 'domain' if they don't want to receive updates for a specific domain
#Add entry to 'email' if they don't want to receive updates for any of their domains
whitelist = {
	'domain':[
		'example.com',
	],
	'email':[
		'test@example.com',
	],
}
