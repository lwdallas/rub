# rub
RUB(a**R**e yo**U** a **B**ad guy) is a golang command line tool to check to see if a site has a ISC suspicious domain entry.

**INSTALLATION** 

`git clone https://github.com/lwdallas/rub.git` 

`go build rub.go`

Copy rub into your path for easy access.

**USAGE** 

`rub domainname` - returns whether the domain is suspicious
Uses info from Internet Storm Center https://isc.sans.edu
(for more info lonnie@lonniewebb.com)

`rub help` - displays a help message.

**OUTPUT** 

If a site is found on the suspiscious domain list the details will be printed along with a **CAUTION** warning of the entry. If it is a false positive there will likely be a Whitelist Detail block explaining why.

If an entry is not found that does not mean it is a safe domain. Other iterations of the domain name may have be used when identifying it.

**Please maintain attribution and share improvements**.