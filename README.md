Hawk Browser Client
===================

Browser client for the Hawk Authentification scheme.

At the time of writing, the client code provided by the Hawk authentification scheme (https://github.com/hueniverse/hawk) does not support browsers out of the box. The main reason being that it makes heavy use of Node's API and some other packages. It also makes use of an NTP server that would be really hard to reproduce. Given that the Hawk specifications mention that in case of a wrong timestamp, the server will provide one, this part can be occulted.

Now, this project is really just a work in progress. I made sure the client unit tests which are used for the client code in Hawk are passing. Currently, all the code has been put in a single class (including helpers) and is mainly composed of code extracted/rewritten from the different libraries that Hawk is currently using. The code for the URL parsing could be a lot shorter as well, but at the moment it's more or less an exact copy of the Browserify (https://github.com/substack/node-browserify) port of Node's url module.

I hope to have the time to rewrite this properly and not leave it as a draft, but in the meantime it can certainly be used as a starting point for people who want to start implementing Hawk on the browser side.

Concerning the licence, because the code uses CryptoJS (https://code.google.com/p/crypto-js/) as an external library and is largely based on Hawk's client code (https://github.com/hueniverse/hawk) as well as Cryptiles (https://github.com/hueniverse/cryptiles) and even a function from Hoek (https://github.com/spumko/hoek), it's fair to say, copyright goes to these people. A proper licence will probably follow when a proper rewrite will have been done.