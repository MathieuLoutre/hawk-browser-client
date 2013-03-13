describe 'Hawk', ->
    describe '#header', ->
        it 'should return a valid authorization header (sha1)', ->
            credentials = 
                id: '123456'
                key: '2983d45yun89q'
                algorithm: 'sha1'

            header = Hawk.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials: credentials, ext: 'Bazinga!', timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about' }).field
            expect(header).toEqual('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="bsvY3IfUllw6V5rvk4tStEvpBhE=", ext="Bazinga!", mac="7C9FoI+X70bBQQiL2E6eYm8b4zE="')

        it 'should return a valid authorization header (sha256)', ->
            credentials = 
                id: '123456'
                key: '2983d45yun89q'
                algorithm: 'sha256'

            header = Hawk.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials: credentials, ext: 'Bazinga!', timestamp: 1353809207, nonce: 'Ygvqdz', payload: 'something to write about', contentType: 'text/plain' }).field;
            expect(header).toEqual('Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", ext="Bazinga!", mac="q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8="')

        it 'should return an empty authorization header on missing options', ->
            header = Hawk.header('https://example.net/somewhere/over/the/rainbow', 'POST').field
            expect(header).toEqual('')

        it 'should return an empty authorization header on invalid credentials', ->
            credentials =
                key: '2983d45yun89q'
                algorithm: 'sha256'

            header = Hawk.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials: credentials, ext: 'Bazinga!', timestamp: 1353809207 }).field
            expect(header).toEqual('')

        it 'should return an empty authorization header on invalid algorithm', ->
            credentials =
                id: '123456'
                key: '2983d45yun89q'
                algorithm: 'hmac-sha-0'

            header = Hawk.header('https://example.net/somewhere/over/the/rainbow', 'POST', { credentials: credentials, payload: 'something, anything!', ext: 'Bazinga!', timestamp: 1353809207 }).field
            expect(header).toEqual('')

    describe '#authenticate', ->
        it 'should return false on invalid header', ->
            res =
                headers: 
                    'server-authorization': 'Hawk mac="abc", bad="xyz"'

            expect(Hawk.authenticate(res, {})).toBe(false)

        it 'should return false on invalid mac', ->
            res =
                headers:
                    'content-type': 'text/plain'
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

        it 'should return true on ignoring hash', ->
            res =
                headers:
                    'content-type': 'text/plain'
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

        it 'should fail on invalid WWW-Authenticate header format', ->
            header = 'Hawk ts="1362346425875", tsm="PhwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", x="Stale timestamp"'
            expect(Hawk.authenticate({ headers: { 'www-authenticate': header } }, {})).toBe(false)

        it 'should fail on invalid WWW-Authenticate header format', ->
            artifacts =
                credentials:
                    id: '123456'
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn'
                    algorithm: 'sha256'
                    user: 'steve'

            header = 'Hawk ts="1362346425875", tsm="hwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", error="Stale timestamp"'
            expect(Hawk.authenticate({ headers: { 'www-authenticate': header } }, artifacts)).toBe(false)
