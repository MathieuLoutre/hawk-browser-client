class Hawk
	@algorithms = ['sha1', 'sha256']
	@headerVersion = '1'

	constructor: -> 

	@header = (uri, method, options) ->
		result =
			field: ''
			artifacts: {}

		# Validate inputs
		if !uri or (typeof uri isnt 'string' and typeof uri isnt 'object') or !method or typeof method isnt 'string' or !options or typeof options isnt 'object'
			return result
	
		credentials = options.credentials

		if !credentials or !credentials.id or !credentials.key or !credentials.algorithm
			return result
		else if this.algorithms.indexOf(credentials.algorithm) is -1
			return result

		# Application time
		timestamp = options.timestamp or Math.floor((Date.now() + (options.localtimeOffsetMsec or 0)) / 1000)
		
		# Parse URI
		uri = parseUri(uri) if typeof uri is 'string'

		# Calculate signature
		artifacts =
			credentials: credentials
			ts: timestamp
			nonce: options.nonce or this.randomString(6)
			method: method
			resource: uri.relative
			host: uri.host
			port: uri.port or (if uri.protocol is 'http' then 80 else 443)
			hash: options.hash
			ext: options.ext
			app: options.app
			dlg: options.dlg

		result.artifacts = artifacts;

		# Calculate payload hash
		if !artifacts.hash and options.payload?
			artifacts.hash = this.calculateHash(options.payload, credentials.algorithm, options.contentType)

		mac = this.calculateMac('header', artifacts)

		# Construct header
		header = "Hawk id=\"#{credentials.id}\", ts=\"#{artifacts.ts}\", nonce=\"#{artifacts.nonce}\""
		header += ", hash=\"#{artifacts.hash}\"" if artifacts.hash
		header += ", ext=\"#{this.escapeHeaderAttribute(artifacts.ext)}\"" if artifacts.ext? and artifacts.ext isnt ''
		header += ", mac=\"#{mac}\""

		if artifacts.app
			header += ", dlg=\"#{artifacts.dlg}\"" if artifacts.dlg
			header += ", app=\"#{artifacts.app}\""

		result.field = header

		return result

	@authenticate: (res, artifacts, options) ->
		artifacts = this.cloneObject(artifacts)
		options = options or {}

		if res.headers['www-authenticate']
			# Parse HTTP WWW-Authenticate header
			attributes = this.parseAuthorizationHeader(res.headers['www-authenticate'], ['ts', 'tsm', 'error'])
			return false if !attributes

			if attributes.ts
				tsm = this.calculateTsMac(attributes.ts, artifacts.credentials)
				return false if !this.fixedTimeComparison(tsm, attributes.tsm)

		# Parse HTTP Server-Authorization header
		return true if !res.headers['server-authorization'] && !options.required

		attributes = this.parseAuthorizationHeader(res.headers['server-authorization'], ['mac', 'ext', 'hash'])
		return false if !attributes

		artifacts.ext = attributes.ext
		artifacts.hash = attributes.hash

		mac = this.calculateMac('response', artifacts)

		return false if !this.fixedTimeComparison(mac, attributes.mac)
		return true if !options.hasOwnProperty('payload')

		calculatedHash = this.calculateHash(options.payload, artifacts.credentials.algorithm, res.headers['content-type'])
		return this.fixedTimeComparison(calculatedHash, attributes.hash)

	@calculateMac: (type, options) ->
		normalized = this.generateNormalizedString(type, options)
		hmac = this.createHmac(options.credentials.algorithm, options.credentials.key)
		hmac = hmac.update(normalized)

		hash = hmac.finalize()

		return hash.toString(CryptoJS.enc.Base64)

	@createHmac: (algo, key) ->
		if algo is 'sha256'
			return CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key)
		else
			return CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA1, key)

	@generateNormalizedString: (type, options) ->
		normalized = 'hawk.' + this.headerVersion + '.' + type + '\n' +
					 options.ts + '\n' +
					 options.nonce + '\n' +
					 options.method.toUpperCase() + '\n' +
					 options.resource + '\n' +
					 options.host.toLowerCase() + '\n' +
					 options.port + '\n' +
					 (options.hash || '') + '\n';

		if options.ext
			normalized += options.ext.replace('\\', '\\\\').replace('\n', '\\n')

		normalized += '\n'

		if options.app
			normalized += options.app + '\n' + (options.dlg || '') + '\n';

		return normalized

	@calculateHash: (payload, algorithm, contentType) ->
		hash = this.createHash(algorithm)

		hash.update('hawk.' + this.headerVersion + '.payload\n')
		hash.update(this.parseContentType(contentType) + '\n')
		hash.update(payload or '')
		hash.update('\n')
		
		hash = hash.finalize()

		return hash.toString(CryptoJS.enc.Base64)

	@createHash: (algo) ->
		if algo is 'sha256'
			return CryptoJS.algo.SHA256.create()
		else
			return CryptoJS.algo.SHA1.create()

	@calculateTsMac = (ts, credentials) ->
		hash = this.createHash(credentials.algorithm)
		hash.update('hawk.' + this.headerVersion + '.ts\n' + ts + '\n');

		hash = hash.finalize()

		return hash.toString(CryptoJS.enc.Base64)

	# Parse Content-Type header content
	@parseContentType: (header) ->
		return '' if !header
		return header.split(';')[0].trim().toLowerCase()

	# Parse Hawk HTTP Authorization header
	@parseAuthorizationHeader: (header, keys) ->
		keys = keys or ['id', 'ts', 'nonce', 'hash', 'ext', 'mac', 'app', 'dlg']
		return false if !header

		headerParts = header.match(/^(\w+)(?:\s+(.*))?$/) # Header: scheme[ something]
		return false if !headerParts

		scheme = headerParts[1]
		return false if scheme.toLowerCase() isnt 'hawk'

		attributesString = headerParts[2]
		return false if !attributesString

		attributes = {}
		verify = attributesString.replace /(\w+)="([^"\\]*)"\s*(?:,\s*|$)/g, ($0, $1, $2) ->
			# Check valid attribute names
			if keys.indexOf($1) is -1 or $2.match(/^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~]+$/) is null or attributes.hasOwnProperty($1)
				return
			else
				attributes[$1] = $2;
				return ''

		if verify isnt ''
			return false
		else
			return attributes

	@cloneObject: (obj) ->
		return null if obj is null or obj is undefined
		return obj if typeof obj isnt 'object'

		newObj = if obj instanceof Array then [] else {}

		for i of obj
			if obj.hasOwnProperty(i)
				if obj[i] instanceof Date
					newObj[i] = new Date(obj[i].getTime())
				else if obj[i] instanceof RegExp
					flags = ''
					flags += 'g' if obj[i].global 
					flags += 'i' if obj[i].ignoreCase
					flags += 'm' if obj[i].multiline
					flags += 'y' if obj[i].sticky

					newObj[i] = new RegExp(obj[i].source, flags)
				else
					newObj[i] = this.cloneObject(obj[i])

		return newObj

	@randomString: (size) ->
		buffer = CryptoJS.lib.WordArray.random(Math.ceil(((size + 1) * 6)/8))
		buffer = buffer.toString(CryptoJS.enc.Base64)

		string = buffer.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
		return string.slice(0, size)

	@fixedTimeComparison: (a, b) ->
		mismatch = (if a.length is b.length then 0 else 1)
		b = a if mismatch

		for i in [0..a.length-1]
			ac = a.charCodeAt(i)
			bc = b.charCodeAt(i)
			mismatch += (if ac is bc then 0 else 1)
		
		return mismatch is 0

	@escapeHeaderAttribute = (attribute) -> attribute.replace(/\\/g, '\\\\').replace(/\"/g, '\\"')