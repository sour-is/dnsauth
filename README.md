dnsauth
=======

DNS Based Authentication 

This project uses TXT records from DNS as a store for public keys which can then be used to authenticate signatures.

Install
-------

The package requires git and mecurial to be installed for go to fetch the dependancies. 

    $ mkdir workspace
    $ export GOPATH=`pwd`
    $ go get github.com/sour-is/dnsauth/dnsauth-cli

The finished executable will be in the bin directory.


Create a DNS entry
------------------

    $ bin/dnsauth-cli gentxt dummy1.sour.is dummy
    
    Private Key: 80ac0b83c0dcc9d91f59e8d865f7e409bad3749d2dcb379431fae3db830101f6f1
    dummy1.sour.is. IN TXT "algo:ecdsa curve:secp256k1 pubkey:BB7OT8hNBSqD8f0atJ6NH-MmZzSQNcSOKSjEjxOlKNHcL8lzVVPt_1XY9b37pZG1jkBn6rZlqCIAKbyc2aTa1P8"

   

Sign a token
------------

    $ bin/dnsauth-cli sign dummy1.sour.is dummy
    
    sig=IHcCY83WQwkS5REJY04yG9OAogq0f2qwiJGYljWyJcKl11-WgqaSU7EO1i3n9axIF0foXPpUqAROsDE6QgfERmkl5q3h


Verify a token
--------------

    $ dnsauth-cli/dnsauth-cli verify dummy1.sour.is IHcCY83WQwkS5REJY04yG9OAogq0f2qwiJGYljWyJcKl11-WgqaSU7EO1i3n9axIF0foXPpUqAROsDE6QgfERmkl5q3h
    
    Verify: true

Using the web interface
-----------------------

    $ dnsauth-cli/dnsauth-cli -v web
    INFO: 2014/05/26 12:28:47 web.go:17: Listen and Serve on port :8080 
    
    $ curl localhost:8080/auth/dummy1.sour.is -d sig=IHcCY83WQwkS5REJY04yG9OAogq0f2qwiJGYljWyJcKl11-WgqaSU7EO1i3n9axIF0foXPpUqAROsDE6QgfERmkl5q3h
    
    INFO: 2014/05/26 12:29:35 web.go:27: Ident: dummy1.sour.is
    INFO: 2014/05/26 12:29:35 web.go:43: PubKey: BB7OT8hNBSqD8f0atJ6NH-MmZzSQNcSOKSjEjxOlKNHcL8lzVVPt_1XY9b37pZG1jkBn6rZlqCIAKbyc2aTa1P8
    INFO: 2014/05/26 12:29:35 web.go:95: Signature: IHcCY83WQwkS5REJY04yG9OAogq0f2qwiJGYljWyJcKl11-WgqaSU7EO1i3n9axIF0foXPpUqAROsDE6QgfERmkl5q3h
    INFO: 2014/05/26 12:29:35 web.go:110: AuthPass: dummy1.sour.is true
    
    {"ident": "dummy1.sour.is", "auth": true}
