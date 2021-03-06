describe 'Hawk', ->

	describe 'client', ->

		describe '#header', ->

			it 'should return a valid authorization header (sha1)', (done) ->
				credentials =
					id: '123456'
					key: '2983d45yun89q'
					algorithm: 'sha1'

				header = Hawk.header('http://example.net/somewhere/over/the/rainbow', 'POST', { credentials: credentials, ext: 'Bazinga!', timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about' }).field
				expect(header).toEqual('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="bsvY3IfUllw6V5rvk4tStEvpBhE=", ext="Bazinga!", mac="qbf1ZPG/r/e06F4ht+T77LXi5vw="')

			it 'should return a valid authorization header (sha256)', (done) ->
				credentials =
					id: '123456'
					key: '2983d45yun89q'
					algorithm: 'sha256'

				header = Hawk.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials: credentials, ext: 'Bazinga!', timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' }).field
				expect(header).toEqual('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", ext="Bazinga!", mac="q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8="')

			it 'should return a valid authorization header (no ext)', (done) ->
				credentials =
					id: '123456'
					key: '2983d45yun89q'
					algorithm: 'sha256'

				header = Hawk.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials: credentials, timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' }).field
				expect(header).toEqual('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="')

			it 'should return an empty authorization header on missing options', (done) ->
				header = Hawk.header('https://example.net/somewhere/over/the/rainbow', 'POST').field
				expect(header).toEqual('')

			it 'should return an empty authorization header on invalid credentials', (done) ->
				credentials =
					key: '2983d45yun89q'
					algorithm: 'sha256'

				header = Hawk.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials: credentials, ext: 'Bazinga!', timestamp: 1353809207 }).field
				expect(header).toEqual('')

			it 'should return an empty authorization header on invalid algorithm', (done) ->
				credentials =
					id: '123456'
					key: '2983d45yun89q'
					algorithm: 'hmac-sha-0'

				header = Hawk.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials: credentials, payload: 'something, anything!', ext: 'Bazinga!', timestamp: 1353809207 }).field
				expect(header).toEqual('')

		describe '#authenticate', ->

			it 'should return false on invalid header', (done) ->
				res =
					headers:
						'server-authorization': 'Hawk mac="abc", bad="xyz"'

				expect(Hawk.authenticate(res, {})).toEqual(false)

			it 'should return false on invalid mac', (done) ->
				res =
					headers:
						'content-type': 'text/plain',
						'server-authorization': 'Hawk mac="_IJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'

				artifacts =
					method: 'POST'
					host: 'example.com'
					port: '8080'
					resource: '/resource/4?filter=a'
					ts: '1362336900'
					nonce: 'eb5S_L'
					hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk='
					ext: 'some-app-data'
					app: undefined
					dlg: undefined
					mac: 'BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk='
					id: '123456'
					credentials:
						id: '123456'
						key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn'
						algorithm: 'sha256'
						user: 'steve'

				expect(Hawk.authenticate(res, artifacts)).toBe(false)

			it 'should return true on ignoring hash', (done) ->
				res =
					headers:
						'content-type': 'text/plain',
						'server-authorization': 'Hawk mac="XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'

				artifacts =
					method: 'POST'
					host: 'example.com'
					port: '8080'
					resource: '/resource/4?filter=a'
					ts: '1362336900'
					nonce: 'eb5S_L'
					hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk='
					ext: 'some-app-data'
					app: undefined
					dlg: undefined
					mac: 'BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk='
					id: '123456'
					credentials:
						id: '123456'
						key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn'
						algorithm: 'sha256'
						user: 'steve'

				expect(Hawk.authenticate(res, artifacts)).toBe(true)

			it 'should fail on invalid WWW-Authenticate header format', (done) ->

				header = 'Hawk ts="1362346425875", tsm="PhwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", x="Stale timestamp"'
				expect(Hawk.authenticate({ headers: { 'www-authenticate': header } }, {})).toBe(false)

			it 'should fail on invalid WWW-Authenticate header format', (done) ->
				artifacts =
					credentials:
						id: '123456'
						key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn'
						algorithm: 'sha256'
						user: 'steve'

				header = 'Hawk ts="1362346425875", tsm="hwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", error="Stale timestamp"'
				expect(Hawk.authenticate({ headers: { 'www-authenticate': header } }, artifacts)).toBe(false)
